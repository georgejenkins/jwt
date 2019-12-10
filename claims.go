package main

import (
	"encoding/json"
	"strconv"
	"time"
)

//Claims contains RFC 7519 Section 4.1 Registered Claim Names all of which are OPTIONAL.
type Claims struct {
	//Issuer.
	Issuer string `json:"iss,omitempty"`

	//Subject
	Subject string `json:"sub,omitempty"`

	//Audience
	Audience string `json:"aud,omitempty"`

	//Expiration Time
	Expiration string `json:"exp,omitempty"`

	//Not Before
	NotBefore string `json:"nbf,omitempty"`

	//Issued At
	IssuedAt string `json:"iat,omitempty"`

	//JWT ID
	JWTID string `json:"jti,omitempty"`
}

func GetClaims(token *Token, outputType interface{}) error {
	return json.Unmarshal(token.RawBody, outputType)
}

// ValidationClaims provides configuration for server-side claim
// validation parameters. These need to be set to expected values
// to vaidate that the tokens issued by from the expected vendor,
// are signed with the expected JWK ID, are for the expected
// audience, and are within the window of validity.
//
// Leeway refers to a short grace period for which the token will be
// considered valid in, if it falls out of the explicit validation period.
// Leeway may be configured for Expiration and/or Not Before to deal with
// time skew.
type ValidationClaims struct {
	JWTID    []string
	Issuer   []string
	Subject  []string
	Audience []string

	// Expiration is provided if a server-side expiration time needs to be
	// set explicitly for each validation attempt. It will otherwise default
	// to the system time.
	Expiration       time.Time
	ExpirationLeeway time.Duration

	NotBefore       time.Time
	NotBeforeLeeway time.Duration
}

// ValidateRegisteredClaims validates registed claims against a
// set of predefined validation parameters.
func (claims *Claims) ValidateRegisteredClaims(validationClaims *ValidationClaims) (bool, error) {
	nbfValid, err := claims.VerifyNotBefore(validationClaims.NotBefore, validationClaims.NotBeforeLeeway)
	if !nbfValid || err != nil {
		return false, err
	}

	expirationValid, err := claims.VerifyExpiration(validationClaims.Expiration, validationClaims.ExpirationLeeway)
	if !expirationValid || err != nil {
		return false, err
	}

	// If no validation claims are provided, we still want to validate the
	// token expiration an nbf values (if they exist). It is for this reason
	// those checks come first.
	if validationClaims == nil {
		return true, nil
	}

	issuerValid := claims.VerifyIssuer(validationClaims.Issuer)
	if !issuerValid {
		return false, nil
	}

	subjectValid := claims.VerifySubject(validationClaims.Subject)
	if !subjectValid {
		return false, nil
	}

	audienceValid := claims.VerifyAudience(validationClaims.Audience)
	if !audienceValid {
		return false, nil
	}

	return true, nil
}

// VerifyIssuer verifies the Issuer (iss) claim, if one exists.
// If it doesn't exist in the claimset, true is returned.
func (claims *Claims) VerifyIssuer(expIssuer []string) bool {
	if claims.Issuer == "" {
		return true
	}

	return anyEquals(expIssuer, claims.Issuer)
}

// VerifySubject verifies the Subject (sub) claim, if one exists.
// If it doesn't exist in the claimset, true is returned.
func (claims *Claims) VerifySubject(expSubject []string) bool {
	if claims.Subject == "" {
		return true
	}

	return anyEquals(expSubject, claims.Subject)
}

// VerifyAudience verifies the Audience (aud) claim, if one exists.
// If it doesn't exist in the claimset, true is returned.
func (claims *Claims) VerifyAudience(expAudience []string) bool {
	if claims.Audience == "" {
		return true
	}

	return anyEquals(expAudience, claims.Audience)
}

// VerifyNotBefore verifies the Not Before ('nbf') claim, if it exists.
// If it doesn't exist in the claimset, true is returned. If there is
// a Not Before claim, it is parsed and compared to the currentTime
// plus any leeway value.
func (claims *Claims) VerifyNotBefore(currentTime time.Time, leeway time.Duration) (bool, error) {
	if claims.NotBefore == "" {
		return true, nil
	}

	timeInt, err := strconv.ParseInt(claims.NotBefore, 10, 64)
	if nil != err {
		return false, err
	}

	nbfClaim := time.Unix(timeInt, 0)
	return (currentTime.Add(leeway).After(nbfClaim)), nil
}

// VerifyExpiration verifies the Expiration ('exp') claim, if it exists.
// If it doesn't exist in the claimset, true is returned. If there is
// a Expiration claim, it is parsed and compared to the currentTime
// plus any leeway value.
func (claims *Claims) VerifyExpiration(currentTime time.Time, leeway time.Duration) (bool, error) {
	if claims.Expiration == "" {
		return true, nil
	}

	timeInt, err := strconv.ParseInt(claims.Expiration, 10, 64)
	if nil != err {
		return false, err
	}

	expClaim := time.Unix(timeInt, 0)
	return (currentTime.Add(-leeway).Before(expClaim)), nil
}

func anyEquals(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}
