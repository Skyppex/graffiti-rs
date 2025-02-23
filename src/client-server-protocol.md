# client-server-protocol

this file documents the protocol for local client-server communication

### communication

as of now, the mode of communication is always `stdio`

### doc style

the documentation uses `graphql`-like types to describe the protocol

## message-format

### headers

`content-type`: string - the mime type of the content part (default: application/vscode-jsonrpc;charset=utf-8)
`content-length`: uint - the length of the content part in bytes. this header is required

### content

the content is found after the first double newline ('\r\n\r\n')

example message

```
content-type: "application/vscode-jsonrpc;charset=utf-8"
content-length: <uint>

{
    "version": "<version>",
    "jsonrpc": "<encoding>",
    "method": "<method-name>",
    "params": <params>
}
```

- `version`: the current protocol version (always 0.1)
- `jsonrpc`: the jsonrpc version of the message (always 2.0)
- `method`: the method type being sent (initialize, edit, move-cursor...)
- `params`: the arguments being passed to the method (depends on the method)

### base types

```graphql
# defines an integer number in the range of -2^31 to 2^31 - 1
scalar Int

# defines an integer number in the range of 0 to 2^32 - 1
scalar UInt

# defines a sequence of characters of arbitrary size
scalar String

# defines any type
scalar Object
```

### abstract message

a general message as defined by JSON-RPC. the local-protocol always
uses “2.0” as the jsonrpc version.

```graphql
interface Message {
  jsonrpc: String!
}
```

### request message

a request message to describe a request between the client and the server.
every processed request must send a response back to the sender of the request.

```graphql
interface Request {
  id: String!
  jsonrpc: String!
  method: String!
  params: Object
}
```

### response message

```graphql
interface Response {
  id: String!
  result: Object
  error: ResponseError
}

type ResponseError {
  code: Int!
  message: String!
  data: Object
}

enum ErrorCodes {
  ParseError # -32700
  InvalidRequest # -32600
  MethodNotFound # -32601
  InvalidParams # -32602
  InternalError # -32603
}
```

### notification message

```graphql
interface Notification {
  method: String!
  params: Object
}
```

## methods

### initialize - request

- method: 'initialize'
- params: `InitializeParams` defined as follows:

```graphql
type InitializeParams {
  process_id: Int
  client_info: ClientInfo
  root_path: String
  # user provided initialization options
  initialize_options: Object
}

type ClientInfo {
  name: String!
  version: String
}
```
