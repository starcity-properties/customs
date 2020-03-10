(ns customs.auth.auth0
  (:require
   [buddy.auth.backends :as backends]
   [buddy.core.keys :as buddy.keys]
   [buddy.sign.jws :as jws]
   [clj-http.client :as client]))


(def ^:private weighted-legacy-roles
  {"legacy:applicant"  0
   "legacy:onboarding" 1
   "legacy:member"     2
   "legacy:admin"      3})


(defn payload->role [payload]
  (letfn [(-most-permissive [permissions]
            (ffirst (sort-by val > (select-keys weighted-legacy-roles permissions))))
          (-permission->role [permission]
            (keyword "account.role" (second (clojure.string/split permission #":" 2))))]
    (if-some [scope (not-empty (:scope payload))]
      (-permission->role scope)
      (-permission->role (-most-permissive (:permissions payload))))))


(defn sub->db-id [sub]
  (Long. (second (clojure.string/split sub #"\|" 2))))


(defn- retrieve-jwks [jwks-uri]
  (let [pkeys (try
                ;; TODO (waiyaki): TTL cache pkeys by their :kid
                (:keys (:body (client/get jwks-uri {:as :json})))
                (catch Exception e
                  (throw
                    (ex-info (or (.getMessage e)
                               "Error retrieving signing keys from JWKS endpoint")
                      {:jwks-uri jwks-uri
                       :message  "Error retrieving signing keys from JWKS endpoint"}))))]
    (if (> (count pkeys) 0)
      pkeys
      (throw (ex-info "JWKS endpoint did not contain any keys"
               {:jwks-uri jwks-uri
                :message  "JWKS endpoint did not contain any keys."})))))


(defn- find-rsa-signing-key [token keys]
  (let [kid         (:kid (jws/decode-header token))
        signing-key (some->> keys
                      (filter #(and
                                 (= "RSA" (:kty %))
                                 (= "sig" (:use %))
                                 (or
                                   (some? (:n %))
                                   (some? (:e %))
                                   (not (empty? (:x5c %))))
                                 (= kid (:kid %))))
                      first
                      buddy.keys/jwk->public-key)]
    (if (some? signing-key)
      signing-key
      (throw (ex-info "JSON Web Key Set contains no RSA signing keys."
               {:message "JWKS contains no RSA signing keys."
                :jwks    keys})))))


(defn backend [jwks-uri token {:keys [options] :as opts}]
  (let [pkey (find-rsa-signing-key token (retrieve-jwks jwks-uri))]
    (backends/jws (merge opts
                    {:secret pkey
                     :options (merge options {:alg :rs256})}))))


(comment
  (require
    '[buddy.auth.backends :as backends]
    '[buddy.sign.jwt :as jwt]
    '[customs.access :as access])

  (def url "https://starcity-dev.auth0.com/.well-known/jwks.json")
  (def auth0-keys (:body (client/get url {:as :json})))
  (def pkey (buddy.keys/jwk->public-key (first (:keys auth0-keys))))

  ;; get any JWT token from auth0 at the starcity-dev domain
  (def t "")

  (def auth-backend (backend url t {:token-name           "Bearer"
                                    :unauthorized-handler access/default-unauthorized}))

  ;; Flip :skip-validation to test with expired tokens
  (jwt/unsign t pkey {:alg             :rs256
                      :skip-validation false})

  (def auth-data (buddy.auth.protocols/-authenticate auth-backend {} t))
  )
