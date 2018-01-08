The Swagger UI tooling allows developers to browse OpenAPI definitions that include endpoints that are protected with OAuth 2 scopes. It includes:

* [Swagger UI](https://github.com/swagger-api/swagger-ui), configured as an OAuth 2.0 client
* A mock OAuth 2.0 authorization endpoint, that supports the [impilicit grant](https://tools.ietf.org/html/rfc6749#section-4.2) only

The Swagger UI will, after authorization with the mock authorization service, present JSON Web Tokens (in an `Authorization` header) to the service described by the OpenAPI definition. The JWTs are signed with a hardcoded ES256 key.

## Usage


### 1. Create a new service in docker-compose.yml

In your `docker-compose.yml`, include a new service:

```yaml
  swaggerui:
    image: amsterdam/oauth2swaggerui
    ports:
      - 8686:8686
```

### 2. Configure your service to use the token verfier key 

You can use this [JSON Web Key Set](https://tools.ietf.org/html/rfc7517#section-5) encoded key to verify the tokens in the service described by the OpenAPI definition:

```json
{
    "keys": [
        {
            "kty": "EC",
            "key_ops": [
                "verify",
                "sign"
            ],
            "kid": "2aedafba-8170-4064-b704-ce92b7c89cc6",
            "crv": "P-256",
            "x": "6r8PYwqfZbq_QzoMA4tzJJsYUIIXdeyPA27qTgEJCDw=",
            "y": "Cf2clfAfFuuCB06NMfIat9ultkMyrMQO9Hd2H7O9ZVE=",
            "d": "N1vu0UQUp0vLfaNeM0EDbl4quvvL6m_ltjoAXXzkI3U="
        }
    ]
}
```

If you work with Django and use the [datapunt-authorization-django](https://pypi.python.org/pypi/datapunt-authorization-django/) middleware, you could include this key in your `settings.py` under:

```python
JWKS_TEST_KEY = """
{
    "keys": [
        {
            "kty": "EC",
            "key_ops": [
                "verify",
                "sign"
            ],
            "kid": "2aedafba-8170-4064-b704-ce92b7c89cc6",
            "crv": "P-256",
            "x": "6r8PYwqfZbq_QzoMA4tzJJsYUIIXdeyPA27qTgEJCDw=",
            "y": "Cf2clfAfFuuCB06NMfIat9ultkMyrMQO9Hd2H7O9ZVE=",
            "d": "N1vu0UQUp0vLfaNeM0EDbl4quvvL6m_ltjoAXXzkI3U="
        }
    ]
}
"""

DATAPUNT_AUTHZ = {
    'JWKS': os.getenv('PUB_JWKS', JWKS_TEST_KEY),
    ...
}
```

### 3. Include OAuth2 security definition in your OpenAPI spec

For OpenAPI v3:

```yaml
components:
  securitySchemes:
    OAuth2:
      type: oauth2
      flows:
        implicit:
          authorizationUrl: 'http://localhost:8686/oauth2/authorize'
          scopes:
            SCOPE1: scope1
            SCOPE2: scope2
            SCOPEN: etc
```

For OpenAPI v2:

```yaml
securityDefinitions:
  OAuth2:
    type: oauth2
    scopes:
        SCOPE1: scope1
        SCOPE2: scope2
        SCOPEN: etc
    flow: implicit
    authorizationUrl: 'http://localhost:8686/oauth2/authorize'
```

Note that you can template the authorizationUrl and serve the spec based on the environment in which the service runs.

### 4. Run Swagger UI

I assume that the service described by your OpenAPI document is running and configured to use the key specified in step 2.

Now run the Swagger UI and point it to your OpenAPI definition:

```shell
$ docker-compose up -d swaggerui
$ open localhost:8686/swagger-ui/?url=[URL_to_openapi_spec]
```

## Troubleshooting

* If Swagger UI is running and your OpenAPI spec isn't loading, check your browser's console for error information.
* One reason for your OpenAPI spec to not load is because your service doensn't allow cross-origin requests. Make sure to send `Access-Control-Allow-Origin` and set it to a value that permits requests from `localhost:8686`.