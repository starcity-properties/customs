(ns customs.auth.auth0
  (:require
   [buddy.auth.backends :as backends]
   [buddy.core.keys :as buddy.keys]
   [buddy.sign.jws :as jws]
   [clj-http.client :as client]
   [clojure.string :as str]))


(def ^:private weighted-legacy-roles
  {"legacy:applicant"  0
   "legacy:onboarding" 1
   "legacy:member"     2
   "legacy:admin"      3})


(defn payload->role [payload]
  (letfn [(-most-permissive [permissions]
            (ffirst (sort-by val > (select-keys weighted-legacy-roles permissions))))
          (-permission->role [permission]
            (keyword "account.role" (second (str/split permission #":" 2))))]
    (if-some [scopes (some-> (:scope payload) not-empty (str/split #" "))]
      (-permission->role (-most-permissive scopes))
      (-permission->role (-most-permissive (:permissions payload))))))


(defn entity-id [payload]
  (java.util.UUID/fromString (second (clojure.string/split (:sub payload) #"\|" 2))))


(defn retrieve-jwks [jwks-uri]
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


(defn rsa-signing-key [header keys]
  (let [kid         (:kid header)
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
  (let [header (jws/decode-header token)]
    (when (not= :rs256 (:alg header))
      (throw (ex-info "Token not signed using RSA."
               {:message "Token not signed using RSA."})))
    (backends/jws (merge opts
                    {:secret  (rsa-signing-key header (retrieve-jwks jwks-uri))
                     :options (merge options {:alg :rs256})}))))
