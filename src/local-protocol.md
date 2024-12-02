# local-protocol

this file documents the protocol for local client-server communication

### communication

as of now, the mode of communication is always `stdio`

### doc style

the documentation uses `graphql`-like types to describe the protocol except
instead of using `!` for required properties, we use `?` for optional properties

## message-format

### headers

`content-length`: uint - the length of the content part in bytes. this header is required
`content-type`: string - the mime type of the content part (default: application/vscode-jsonrpc;charset=utf-8)

### content

the content is found after a double newline ('\r\n\r\n')

example message

```
content-length: <uint>\r\n
\r\n
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

## methods

### initialize
