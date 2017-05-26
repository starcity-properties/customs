(ns customs.auth
  (:require [buddy.core
             [codecs :refer [bytes->hex]]
             [hash :refer [md5]]]
            [buddy.hashers :as hashers]
            [clojure.spec :as s]
            [datomic.api :as d]
            [toolbelt.predicates :as p]))

(defn hash-password
  "Generate a hash for `password`."
  [password]
  (hashers/derive password {:alg :bcrypt+blake2b-512 :iterations 12}))

(defn matching-password?
  "Does `password` match the `hash`?"
  [password hash]
  (hashers/check password hash))

(defn random-password
  "With no args, produces a random string of 8 characters. `n` can optionally be
  specified."
  ([]
   (random-password 8))
  ([n]
   (let [chars    (concat
                   (map char (range 48 58))
                   (map char (range 65 91))
                   (map char (range 97 123)))
         password (take n (repeatedly #(rand-nth chars)))]
     (reduce str password))))

(defn session-data
  "Produce the data that should be stored in the session for `account`."
  [account]
  {:account/email      (:account/email account)
   :account/role       (:account/role account)
   :account/activated  (:account/activated account)
   :account/first-name (:account/first-name account)
   :account/last-name  (:account/last-name account)
   :db/id              (:db/id account)})

(defn change-password
  "Change the password for `account` to `new-password`. `new-password` will be
  hashed before it is saved to db."
  [account new-password]
  {:db/id (:db/id account) :account/password (hash-password new-password)})

(s/fdef change-password
        :args (s/cat :account p/entity?
                     :new-password string?)
        :ret map?)

(defn reset-password
  "Reset the password for `account` by generating a random password. Return the
  generated password."
  [account]
  (let [new-password (random-password)]
    [new-password (change-password account new-password)]))

(s/fdef reset-password
        :args (s/cat :account p/entity?)
        :ret (s/cat :new-password string? :tx-data map?))

(defn is-password?
  "Does `password` the correct password for this `account`?"
  [account password]
  (let [hash (:account/password account)]
    (matching-password? password hash)))

(s/fdef is-password?
        :args (s/cat :account p/entity?
                     :password string?)
        :ret boolean?)

(defn authenticate
  "Return the user record found under `email` iff a user record exists for
  that email and the `password` matches."
  [db email password]
  (when-let [account (d/entity db [:account/email email])]
    (when (matching-password? password (:account/password account))
     (session-data account))))

(s/fdef authenticate
        :args (s/cat :db p/db? :email string? :password string?)
        :ret (s/or :nothing nil? :data map?))

(defn make-activation-hash
  "Generate an activation hash for `account`."
  [email]
  (-> email
      (str (System/currentTimeMillis))
      (md5)
      (bytes->hex)))

(defn activate
  "Indicate that the user has successfully verified ownership over the provided
  email address."
  [account]
  {:db/id             (:db/id account)
   :account/activated true})

(s/fdef activate
        :args (s/cat :account p/entity?)
        :ret map?)
