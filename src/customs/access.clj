(ns customs.access
  (:require [buddy.auth :as buddy.auth :refer [authenticated? throw-unauthorized]]
            [buddy.auth.accessrules :refer [error success]]
            [buddy.auth.backends.session :refer [session-backend]]
            [buddy.auth.backends :as backends]
            [buddy.auth.protocols :as protocols]))

;; =============================================================================
;; Constants
;; =============================================================================

(def ^:private permissions {})

;; =============================================================================
;; Access Rules
;; =============================================================================

(defn- get-role [req]
  (let [identity (or (:identity req)
                     (get-in req [:session :identity]))]
    (:account/role identity)))

(defn authenticated-user [req]
  (if (authenticated? req)
    true
    (throw-unauthorized)))

(defn unauthenticated-user [req]
  (not (authenticated? req)))

(defn user-can
  "Given a particular action that the authenticated user desires to perform,
  return a handler that determines if their user level is authorized to perform
  that action."
  [action]
  (fn [req]
    (let [user-role      (get-role req)
          required-roles (get permissions action #{})]
      (if (some #(isa? user-role %) required-roles)
        (success)
        (error (format "User with role %s is not authorized for action %s"
                       (name user-role) (name action)))))))

(defn user-isa
  "Return a handler that determines whether the authenticated user is of a
  specific role OR any derived role."
  [role]
  (fn [req]
    (if (isa? (get-role req) role)
      (success)
      (error (format "User is not a(n) %s" (name role))))))

(defn user-is
  "Return a handler that determines whether the authenticated user is of a
  specific role."
  [role]
  (fn [req]
    (if (= (get-role req) role)
      (success)
      (error (format "User is not a(n) %s" (name role))))))

(defn user-has-id
  "Return a handler that determines whether the authenticated user has a given ID.
  This is useful, for example, to determine if the user is the owner of the
  requested resource."
  [id]
  (fn [req]
    (if (= id (get-in req [:identity :db/id]))
      (success)
      (error (str "User does not have id given %s" id)))))

;; =============================================================================
;; Auth Backend
;; =============================================================================

(defn- response [body status]
  {:status  status
   :body    body
   :headers {"Content-Type" "text/html; charset=utf-8"}})

(defn- default-unauthorized [{:keys [headers] :as request} metadata]
  (if (authenticated? request)
    (response "You are not authorized to view this page." 403)
    (response "You are not authenticated; please log in." 401)))

(defn auth-backend
  "Authentication/authorization backend for ring middlewares."
  [& {:keys [unauthorized-handler]}]
  (session-backend {:unauthorized-handler (or unauthorized-handler default-unauthorized)}))

(defn auth-backend-jws
  "Authentication/authorization backend that uses signed self contained tokens (signed JWT)
  to authenticate.

  Will accept a valid JWT token in a cookie, or the Authorization header. Returns a map
  representing an account entity in the Starcity system with selected keys;
  #{:db/id :account/email :account/role}

  See more about signed JWT on https://funcool.github.io/buddy-auth/latest/#signed-jwt"
  [& {:keys [unauthorized-handler cookie-name] :as opts
      :or   {unauthorized-handler default-unauthorized} }]
  (let [default-backend (backends/jws (merge opts
                                             {:unauthorized-handler unauthorized-handler}))]
    (reify

      protocols/IAuthentication
      (-parse [_ request]
        (letfn [(-parse-cookie [{:keys [cookies oauth2/access-tokens]}]
                  (get-in cookies [cookie-name :value]))]
          (or (-parse-cookie request)
              (protocols/-parse default-backend request))))
      (-authenticate [_ request data]
        (when-some [auth-data (protocols/-authenticate default-backend request data)]
          ;; The JWT has been validated, so we'll transform the standard JWT fields to a map
          ;; representing an account entity in our system
          {:db/id         (:sub auth-data)
           ;; Keywords become strings when signed, so make it a keyword again.
           :account/role  (keyword (:role auth-data))}))

      protocols/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (protocols/-handle-unauthorized default-backend request metadata)))))

(defn oauth2-backend-jws
  "Authentication/authorization backend that uses signed self contained tokens (signed JWT)
  to authenticate.

  Will accept a valid JWT token in a cookie, or the Authorization header. Returns a map
  representing an account entity in the Starcity system with selected keys;
  #{:db/id :account/email :account/role}

  See more about signed JWT on https://funcool.github.io/buddy-auth/latest/#signed-jwt"
  [& {:keys [unauthorized-handler oauth2-service] :as opts
      :or   {unauthorized-handler default-unauthorized} }]
  (let [default-backend (backends/jws (merge opts
                                             {:token-name           "Bearer"
                                              :unauthorized-handler unauthorized-handler}))]
    (reify

      protocols/IAuthentication
      (-parse [_ request]
        (letfn []
          (or (get-in request [:oauth2/access-tokens oauth2-service :token])
              (protocols/-parse default-backend request))))
      (-authenticate [_ request data]
        (when-some [auth-data (protocols/-authenticate default-backend request data)]
          ;; The JWT has been validated, so we'll transform the standard JWT fields to a map
          ;; representing an account entity in our system
          {:db/id         (:sub auth-data)
           ;; Keywords become strings when signed, so make it a keyword again.
           :account/role  (keyword (:role auth-data))}))

      protocols/IAuthorization
      (-handle-unauthorized [_ request metadata]
        (protocols/-handle-unauthorized default-backend request metadata)))))
