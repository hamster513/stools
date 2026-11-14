/** Download local data without sending it to the server or embedding it in navigation URLs. */
export function downloadLocal(name:string,data:string|Uint8Array,type='text/plain;charset=utf-8') {
  const blob=new Blob([typeof data==='string'?data:data.slice().buffer],{type})
  const url=URL.createObjectURL(blob),a=document.createElement('a')
  a.href=url;a.download=name;a.click()
  setTimeout(()=>URL.revokeObjectURL(url),1000)
}
