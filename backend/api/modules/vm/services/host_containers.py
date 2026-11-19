"""Containers observed by MaxPatrol, enriched by verified Harbor image IDs."""
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


# Count, page and snapshot metadata belong to one PostgreSQL statement so a
# concurrent snapshot replacement cannot mix two inventories in one response.
_LIST = text("""
    WITH snapshot AS (
        SELECT collected_at, attempted_at, error FROM vm_docker_snapshot WHERE id = 1
    ), observed AS (
        SELECT h.host->>'hostname' AS hostname, coalesce(h.host->>'ip', '') AS ip,
               o.asset_id, d.id AS image_row_id, d.image_id, d.title, d.collected_at,
               c.item AS container, c.item->>'id' AS container_id,
               coalesce(nullif(c.item->>'status', ''), 'unknown') AS status,
               CASE WHEN json_array_length(c.item->'references') > 0 THEN c.item->'references'
                    ELSE coalesce(d.details->'references', '[]'::json) END AS refs,
               CASE WHEN json_array_length(c.item->'references') > 0 THEN 'container'
                    WHEN json_array_length(d.details->'references') > 0 THEN 'image'
                    ELSE 'unknown' END AS refs_source
        FROM vm_docker_image d
        CROSS JOIN LATERAL json_array_elements(d.details->'hosts') AS h(host)
        CROSS JOIN LATERAL json_array_elements(h.host->'containers') AS c(item)
        LEFT JOIN asset_observation o ON :with_assets AND o.source = 'vm' AND o.gone_at IS NULL
            AND o.source_key = (h.host->>'hostname') || '|' || coalesce(h.host->>'ip', '')
        WHERE EXISTS (SELECT 1 FROM snapshot WHERE collected_at IS NOT NULL)
          AND (CAST(:asset_id AS integer) IS NULL OR o.asset_id = :asset_id)
    ), ranked AS (
        SELECT observed.*,
               row_number() OVER (identity ORDER BY (image_id = ''), image_row_id) AS position,
               min(nullif(image_id, '')) OVER identity IS DISTINCT FROM
                   max(nullif(image_id, '')) OVER identity AS conflicting_image,
               min(status) OVER identity IS DISTINCT FROM max(status) OVER identity AS conflicting_status
        FROM observed
        WINDOW identity AS (PARTITION BY hostname, ip, container_id)
    ), harbor_refs AS (
        SELECT DISTINCT r.image_id, i.id, i.project, i.repository FROM vm_image i
        CROSS JOIN LATERAL json_array_elements_text(i.runtime_ids) AS r(image_id)
        WHERE i.artifact_kind NOT IN ('helm', 'other') AND r.image_id <> ''
    ), verified AS (
        SELECT DISTINCT image_id FROM harbor_refs
    ), inventory AS (
        SELECT hostname, ip, asset_id, collected_at,
               CASE WHEN NOT conflicting_image THEN image_row_id END AS image_row_id,
               CASE WHEN conflicting_image THEN '' ELSE r.image_id END AS image_id,
               CASE WHEN conflicting_image THEN 'Образ не определён' ELSE title END AS title,
               CASE WHEN conflicting_image THEN '[]'::json ELSE refs END AS references,
               CASE WHEN conflicting_image THEN 'unknown' ELSE refs_source END AS references_source,
               (CAST(container AS jsonb) - 'references') || jsonb_build_object(
                   'status', CASE WHEN conflicting_status THEN 'unknown' ELSE status END
               ) AS container,
               v.image_id IS NOT NULL AS harbor_matched
        FROM ranked r LEFT JOIN verified v ON NOT conflicting_image AND v.image_id = r.image_id
        WHERE position = 1
    ), filtered AS (
        SELECT * FROM inventory
        WHERE (NOT :running_only OR container->>'status' = 'running')
          AND (NOT :unmatched_only OR NOT harbor_matched)
          AND (:q = '' OR strpos(lower(concat_ws(' ', hostname, ip, container->>'name',
                   container->>'id', image_id)), lower(:q)) > 0
               OR EXISTS (
                   SELECT 1 FROM json_array_elements(inventory.references) AS ref(value)
                   WHERE strpos(lower(concat_ws('/', nullif(value->>'registry', ''), value->>'repo')
                             || coalesce(':' || (value->>'tag'), '')), lower(:q)) > 0
               ))
    ), page AS (
        SELECT * FROM filtered
        ORDER BY hostname, ip, container->>'name', container->>'id' LIMIT :limit OFFSET :offset
    ), links AS (
        SELECT r.image_id,
               json_agg(json_build_object('id', r.id, 'project', r.project, 'repository', r.repository)
                        ORDER BY r.project, r.repository, r.id) AS images
        FROM harbor_refs r JOIN (SELECT DISTINCT image_id FROM page WHERE harbor_matched) p USING (image_id)
        GROUP BY r.image_id
    ), enriched AS (
        SELECT p.*, coalesce(links.images, '[]'::json) AS harbor_images
        FROM page p LEFT JOIN links USING (image_id)
    )
    SELECT (SELECT count(*) FROM filtered) AS total,
           coalesce((SELECT json_agg(p ORDER BY hostname, ip, container->>'name', container->>'id')
                     FROM enriched p), '[]'::json) AS items,
           (SELECT row_to_json(s) FROM snapshot s) AS mp_vm,
           (SELECT json_build_object('id', id, 'name', name) FROM asset WHERE id = :asset_id) AS asset
""")


def by_host(
    db: Session, *, asset_id: int | None, q: str, running_only: bool, unmatched_only: bool,
    limit: int, offset: int, with_assets: bool = True,
) -> dict[str, Any]:
    row = db.execute(_LIST, {"asset_id": asset_id, "q": q.strip(), "running_only": running_only,
                            "unmatched_only": unmatched_only, "limit": limit, "offset": offset,
                            "with_assets": with_assets}).mappings().one()
    return dict(row)
