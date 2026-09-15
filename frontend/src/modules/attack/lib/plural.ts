/** «12 хостов», «1 хост», «3 хоста» — формы приходят с сервера вместе со слоем. */
export function plural(n: number, forms: [string, string, string]): string {
  const mod10 = n % 10
  const mod100 = n % 100
  const form =
    mod10 === 1 && mod100 !== 11
      ? forms[0]
      : mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)
        ? forms[1]
        : forms[2]
  return `${n} ${form}`
}
