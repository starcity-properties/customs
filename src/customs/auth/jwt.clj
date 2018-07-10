(ns customs.auth.jwt
  (:require [buddy.sign.jwt :as jwt]
            [clj-time.coerce :as c]
            [clj-time.core :as t]
            [clojure.spec.alpha :as s]))

(defn- claims
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

  [eid role {:keys [iss aud max-age]}]
  (let [-date->secs #(-> (c/to-long %)
                         (/ 1000)
                         long)
        issued-at   (-date->secs (t/now))
        expires-at  (-date->secs (t/plus (t/now) (t/seconds (or max-age 60))))]
    {:iss  iss
     :aud  aud
     :iat  issued-at
     :nbf  issued-at
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

  Options:
  :iss      - URI of the issuer. Required.
  :aud      - Collection of URIs of the recipients of the token. Required.
  :max-age  - Interval in seconds the token is valid from when it's issued.
              Optional (default 60 secs)."
  [account secret opts]
  (jwt/sign (claims (:db/id account)
                    (:account/role account)
                    opts)
            secret))
