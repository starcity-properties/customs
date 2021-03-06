(ns customs.auth.jwt
  (:require
   [buddy.auth.protocols :as protocols]
   [buddy.auth.backends :as backends]
   [buddy.core.keys :as buddy.keys]
   [buddy.sign.jwt :as jwt]
   [buddy.sign.jws :as jws]
   [clj-time.coerce :as c]
   [clj-time.core :as t]
   [clojure.spec.alpha :as s]
   [customs.access :as access]
   [customs.auth.auth0 :as auth0]))

(defn claims
  "Returns a map with our JWT claims, given the eid and role of the account:

  Registered claims:
  :iss (issuer)     - URI of the issuer of the JWT (Auth service).
  :aud (audience)   - Collection of URIs of the recipients the JWT is intended for (e.g. API server).
                      The JWT must be rejected if consumer does not identify as the audience.
  :iat (issued at)  - Unix time in seconds at which the token was issued.
  :nbf (not before) - Unix time in seconds before which the JWT must NOT be accepted.
  :exp (expires at) - Unix time in seconds after which the JWT must NOT be accepted.
  :sub (subject)    - Identifier for the subject of the token (an account).

  More about registered claims: https://tools.ietf.org/html/rfc7519#section-4
  The IANA JSON Web Token Registry: https://www.iana.org/assignments/jwt/jwt.xhtml"

  [eid role {:keys [iss aud max-age iat exp nbf]}]
  (let [-date->secs #(-> (c/to-long %)
                       (/ 1000)
                       long)
        issued-at   (or iat (-date->secs (t/now)))
        not-before  (or nbf issued-at)
        expires-at  (or exp (-date->secs (t/plus (t/now) (t/seconds (or max-age 3600)))))]
    {:iss  iss
     :aud  aud
     :iat  issued-at
     :nbf  not-before
     :exp  expires-at
     :sub  eid
     :role role}))

(s/def ::iss string?)
(s/def ::aud (s/coll-of string?))
(s/def ::iat (s/and pos? number?))
(s/def ::nbf (s/and pos? number?))
(s/def ::exp (s/and pos? number?))
(s/def ::sub (s/and pos? number?))
(s/def ::max-age (s/and pos? number?))
(s/def ::role keyword?)

(s/def ::jwt-claims (s/keys :req-un [::iss ::aud ::iat ::nbf ::exp ::sub ::role]))
(s/fdef claims
  :args (s/cat :eid (s/and pos? number?)
          :role ::role
          :opts (s/keys :req-un [::iss ::aud ::max-age]))
  :ret ::jwt-claims)

;; ==============================================================================
;; sign =========================================================================
;; ==============================================================================


(defn sign
  "Produce a signed JWT given an account, secret and options.
  2 arity: sign the supplied `use-claims` with the `secret`.

  Options:
  :iss      - URI of the issuer. Required.
  :aud      - Collection of URIs of the recipients of the token. Required.
  :iat      - Unix time in seconds at which the token was issued.
  :nbf      - Unix time in seconds before which the JWT must NOT be accepted.
  :exp      - Unix time in seconds after which the JWT must NOT be accepted.
  :max-age  - Interval in seconds the token is valid from when it's issued.
              Optional (default 3600 secs)."
  ([use-claims secret]
   (jwt/sign use-claims secret))
  ([account secret options]
   (jwt/sign (claims (:db/id account) (:account/role account) options) secret)))


(defn unsign
  "Produce a signed JWT given an account, secret and options.

  Options:
  :iss      - Validates that token's :iss matches the provided iss.
  :aud      - Validates that token's :aud contains the provided aud
  :max-age  - Validates that the token is not older than the provided :max-age."
  [data secret options]
  (-> (jwt/unsign data secret options)
    (update :role keyword)))


;; ==============================================================================
;; Backends =====================================================================
;; ==============================================================================


(defn- parse [request backend]
  (letfn [(-parse-oauth2 [{:oauth2/keys [access-tokens]}]
            (get access-tokens :token))]
    (or (-parse-oauth2 request)
      (protocols/-parse backend request))))


(defn oauth2-backend
  "Authentication/authorization backend that uses signed self contained tokens (signed JWT)
  to authenticate.

  Will accept a valid JWT token in a cookie, or the Authorization header. Returns a map
  representing an account entity in the Starcity system with selected keys;
  #{:db/id :account/email :account/role}

  See more about signed JWT on https://funcool.github.io/buddy-auth/latest/#signed-jwt"
  [{:keys [unauthorized-handler] :as opts
    :or   {unauthorized-handler access/default-unauthorized}}]
  (let [default-backend (backends/jws (merge opts
                                        {:token-name           "Bearer"
                                         :unauthorized-handler unauthorized-handler}))]
    (reify

      protocols/IAuthentication
      (-parse [_ request]
        (parse request default-backend))
      (-authenticate [_ request data]
        (when-some [auth-data (protocols/-authenticate default-backend request data)]
          ;; The JWT has been validated, so we'll transform the standard JWT fields to a map
          ;; representing an account entity in our system
          {:db/id        (:sub auth-data)
           ;; Keywords become strings when signed, so make it a keyword again.
           :account/role (keyword (:role auth-data))}))

      protocols/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (protocols/-handle-unauthorized default-backend request metadata)))))


(defn auth0-oauth2-backend
  [{:keys [jwks-uri unauthorized-handler] :as opts
    :or   {unauthorized-handler access/default-unauthorized}}]
  (let [default-opts    (merge opts
                          {:token-name           "Bearer"
                           :unauthorized-handler unauthorized-handler})
        default-backend (backends/jws default-opts)]
    (reify

      protocols/IAuthentication
      (-parse [_ request]
        (parse request default-backend))
      (-authenticate [_ request data]
        (try
          (let [backend (auth0/backend jwks-uri data default-opts)]
            (when-some [auth-data (protocols/-authenticate backend request data)]
              ;; The JWT has been validated, so we'll transform the standard JWT fields to a map
              ;; representing an account entity in our system
              (if (= "client-credentials" (:gty auth-data))
                (assoc auth-data :account/role (auth0/payload->role auth-data))
                {:account/id   (auth0/entity-id auth-data)
                 :account/role (auth0/payload->role auth-data)})))
          (catch Exception e
            ;; Unable to authenticate via Auth0
            nil)))

      protocols/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (protocols/-handle-unauthorized default-backend request metadata)))))

(comment
  (require
    '[buddy.auth.backends :as backends]
    '[buddy.sign.jwt :as jwt]
    '[customs.access :as access]
    '[clj-http.client :as client])

  (def url "https://starcity-dev.auth0.com/.well-known/jwks.json")
  (def auth0-keys (:body (client/get url {:as :json})))
  (def pkey (buddy.keys/jwk->public-key (first (:keys auth0-keys))))

  ;; get any JWT token from auth0 at the starcity-dev domain
  (def t "")


  (def auth-backend (auth0-oauth2-backend {:jwks-uri url}))

  ;; Flip :skip-validation to test with expired tokens
  (jwt/unsign t pkey {:alg             :rs256
                      :skip-validation false})

  (def auth-data (buddy.auth.protocols/-authenticate auth-backend {} t))
  (prn auth-data)
  )
