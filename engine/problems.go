package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/thelemail/export-tool/transfer"
	"github.com/thelemail/migrator/engine/internal/backup"
	"github.com/thelemail/migrator/engine/internal/config"
	"github.com/thelemail/migrator/engine/internal/destination"
	"github.com/thelemail/migrator/engine/internal/session"
	"github.com/thelemail/migrator/engine/internal/source"
)

type problem struct {
	code, message string
}

func authHost() string {
	if u, err := url.Parse(config.Auth); err == nil && u.Host != "" {
		return u.Host
	}
	return config.Auth
}

func describe(err error) problem {
	var wait *transfer.WaitError
	var status destination.StatusError
	var netErr net.Error
	var signIn *source.SignInError
	var connect *source.ConnectError
	var partial *backup.Incomplete
	switch {
	case errors.Is(err, transfer.ErrSessionEnded):
		return problem{"session_ended", "Your Thelemail session ended. Sign in again to continue. The transfer picks up where it stopped."}
	case errors.As(err, &wait):
		return problem{"rate_limited", fmt.Sprintf("Too many sign-in attempts. Try again in %s.", humanWait(wait.Wait))}
	case errors.Is(err, transfer.ErrWrongPassword):
		return problem{"wrong_password", fmt.Sprintf("The email address or password is incorrect. If your account is older, sign in once at %s, then try again here.", authHost())}
	case errors.Is(err, transfer.ErrUpgradeRequired):
		return problem{"upgrade_required", fmt.Sprintf("Your account needs a security upgrade first. Sign in at %s, then come back to Migrator.", authHost())}
	case errors.Is(err, transfer.ErrSuspended):
		return problem{"suspended", "This account is suspended, so Migrator can't sign in. Contact Thelemail support."}
	case errors.Is(err, transfer.ErrProofFailed):
		return problem{"proof_failed", "The sign-in check couldn't be completed. Try again."}
	case errors.Is(err, transfer.ErrVerificationExpired), errors.Is(err, context.DeadlineExceeded):
		return problem{"verification_expired", "Verification took too long. Sign in again."}
	case errors.Is(err, transfer.ErrNoSecondFactor):
		return problem{"no_second_factor", fmt.Sprintf("None of your verification methods works in Migrator. Add an authenticator app or a passkey at %s.", authHost())}
	case errors.Is(err, session.ErrPasskeyCancelled):
		return problem{"passkey_cancelled", "Passkey verification was cancelled. Try again or choose another method."}
	case errors.Is(err, session.ErrKeysUnverified):
		return problem{"keys_unverified", "Migrator couldn't verify your account keys, so it won't import mail right now. Export still works. Try again in a few minutes."}
	case errors.As(err, &signIn):
		return problem{"source_sign_in", "Your old mailbox didn't accept the sign-in. " + passwordTip(signIn.Host)}
	case errors.Is(err, source.ErrSourceSignIn):
		return problem{"source_sign_in", "Your old mailbox didn't accept the sign-in. " + passwordTip("")}
	case errors.As(err, &connect):
		security := "SSL/TLS"
		if connect.StartTLS {
			security = "STARTTLS"
		}
		return problem{"source_connect", fmt.Sprintf("Migrator couldn't connect to %s using %s. Check the server name, the port and the connection security. Most providers use port 993 with SSL/TLS.", connect.Address, security)}
	case errors.As(err, &partial) && partial.Pending > 0:
		return problem{"export_incomplete", fmt.Sprintf("The export stopped before %s could be saved. Run the export again with the same folder to finish it.", messages(partial.Pending))}
	case errors.As(err, &partial) && partial.KeyProblems:
		return problem{"export_keys", "The export finished, but some of your keys couldn't be checked. Run the export again with the same folder. Details are in export-report.json."}
	case errors.As(err, &partial):
		return problem{"export_unreadable", fmt.Sprintf("The export finished, but %s couldn't be decrypted. They're marked in the export and listed in export-report.json in the export folder.", messages(partial.Lost))}
	case errors.Is(err, destination.ErrFolderRejected):
		return problem{"folder_rejected", "A folder or label was removed in Thelemail during the transfer. Start the transfer again to recreate it."}
	case errors.As(err, &status) && status == http.StatusInsufficientStorage:
		return problem{"quota", "Your Thelemail storage is full. Free some space or upgrade your plan, then start the transfer again."}
	case errors.As(err, &status) && status == http.StatusRequestEntityTooLarge:
		return problem{"too_large", "A message is larger than Thelemail accepts. Start the transfer again to skip past it."}
	case errors.As(err, &status) && status == http.StatusUnauthorized:
		return problem{"session_ended", "Your Thelemail session ended. Sign in again to continue. The transfer picks up where it stopped."}
	case errors.As(err, &netErr), errors.Is(err, net.ErrClosed):
		return problem{"network", "Migrator couldn't reach the server. Check your connection and try again."}
	}
	return problem{"error", "Something went wrong. Open the details for more."}
}

func messages(n int) string {
	if n == 1 {
		return "1 message"
	}
	return fmt.Sprintf("%d messages", n)
}

func passwordTip(host string) string {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	within := func(domains ...string) bool {
		for _, d := range domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return true
			}
		}
		return false
	}
	switch {
	case within("fastmail.com", "messagingengine.com"):
		return "Fastmail needs an app password with Mail access: Settings, then Privacy & Security, then App passwords. Use your full Fastmail address as the login."
	case within("gmail.com", "googlemail.com"):
		return "Gmail needs an app password: turn on 2-Step Verification in your Google Account, then create one under App passwords. Use your full Gmail address as the login."
	case within("me.com", "icloud.com", "mac.com"):
		return "iCloud Mail needs an app-specific password from account.apple.com. Use your iCloud email address as the login."
	case within("yahoo.com", "yahoodns.net", "aol.com"):
		return "Yahoo and AOL need an app password from your account security settings. Use your full email address as the login."
	case within("outlook.com", "office365.com", "hotmail.com", "live.com"):
		return "Outlook.com and Microsoft 365 no longer accept passwords over IMAP, so Migrator can't sign in. Export your mail as MBOX or EML files instead and import those."
	}
	return "Check the login and password. Many providers need an app password for IMAP instead of your normal password."
}

func humanWait(d time.Duration) string {
	switch {
	case d <= 0:
		return "a few minutes"
	case d < time.Minute:
		return "less than a minute"
	case d < 2*time.Minute:
		return "a minute"
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int((d+time.Minute-1)/time.Minute))
	case d < 2*time.Hour:
		return "an hour"
	default:
		return fmt.Sprintf("%d hours", int((d+time.Hour-1)/time.Hour))
	}
}

func logLine(code string, err error) string {
	status := transfer.HTTPStatus(err)
	var own destination.StatusError
	if status == 0 && errors.As(err, &own) {
		status = int(own)
	}
	if status == 0 {
		return code
	}
	return fmt.Sprintf("%s (HTTP %d)", code, status)
}

func detail(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}
