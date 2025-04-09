# mtls-cert

Flex Gateway custom policy for extracting client certificate details and exposing them upstream in headers 

## Preparing the policy for the build

Once the repository is cloned to your local drive, modify the following file with your own Anypoint Org id, or your Business Group id.
- Cargo.toml
  replace the assigned value with your designated org/BU id:
  ```
  group_id = "aaaaaaaa-bbbb-cccc-0000-dddddddddddd"
  ```
 

## Test the Policy

Test the policy using either integration testing or the policy playground.

To find the prereqs for using either environment and to learn more about either environment, see:

* [Writing Integration Tests](https://docs.mulesoft.com/pdk/latest/policies-pdk-integration-tests).
* [Debug Policies With the PDK Playground](https://docs.mulesoft.com/pdk/latest/policies-pdk-debug-local).

### Integration Testing

This example contains an [integration test](./tests/requests.rs) to simplify its testing. To begin testing:

1. Add the `registration.yaml` in the `./tests/common` folder.

The test can be invoked by using the `test` command:
2. Execute the `test` command:

``` shell
make test
```

### Playground Testing

To use the policy in the playground:

1. Add the `registration.yaml` in the `./playground/config` folder

2. Execute the `run` command to begin testing:

``` shell
make run
```

3. Make requests to the Flex Gateway by using the following Curl command:

```shell
curl "https://localhost:8081" --cacert ./tests/resources/server.crt --cert ./tests/resources/client.pem --key ./tests/resources/client.key  -v
```
Flex Gateway should return a response with the email and name as headers:

```json
{
  "args": {}, 
  "data": "", 
  "files": {}, 
  "form": {}, 
  "headers": {
    "Accept": "*/*", 
    "Host": "backend", 
    "User-Agent": "curl/8.4.0", 
    "X-Envoy-Expected-Rq-Timeout-Ms": "15000", 
    "X-Envoy-Internal": "true", 
    "X-Envoy-Original-Path": "/", 
    "X-Peer-Email": "joker@phantomthieves.com", 
    "X-Peer-Name": "Joker"
  }, 
  "json": null, 
  "method": "GET", 
  "origin": "192.168.65.1", 
  "url": "https://backend/anything/echo/"
}
```
