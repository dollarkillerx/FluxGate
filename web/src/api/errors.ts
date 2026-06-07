/** JSON-RPC error carrying the spec error code. */
export class RpcError extends Error {
  code: number
  constructor(code: number, message: string) {
    super(message)
    this.name = 'RpcError'
    this.code = code
  }
}
