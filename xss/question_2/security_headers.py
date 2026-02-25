from typing import Callable
from starlette.types import ASGIApp, Receive, Scope, Send
import secrets

class SecurityHeadersMiddleware:
	def __init__(self, app: ASGIApp):
		self.app = app

	def src_nonce(self):

		return secrets.token_urlsafe(44)

	async def __call__(self, scope: Scope, receive: Receive, send: Send):
		async def send_wrapper(message):
			if message["type"] == "http.response.start":
				headers = dict(message.get("headers", []))

				def set_header(name: str, value: str):
					headers[name.lower().encode()] = value.encode()


				# (2) X-Content-Type-Options
				set_header("x-content-type-options", "nosniff")

				# XSS-Protection

				set_header("x-xss-protection",1)

				nonce = self.src_nonce()

				# (6) Content-Security-Policy (CSP)
				csp = (
					"default-src 'self'; "
					"style-src 'self' ; "
					f"script-src 'nonce-{nonce} 'strict-dynamic'; "
				)
				set_header("content-security-policy", csp)

				# (7) Cross-Origin-Opener-Policy
				set_header("cross-origin-opener-policy", "same-origin")

				# (8) Cross-Origin-Resource-Policy
				set_header("cross-origin-resource-policy", "same-origin")

				# (9) Cross-Origin-Embedder-Policy
				set_header("cross-origin-embedder-policy", "require-corp")

				# (10) Cache-Control (for APIs)
				set_header(
					"cache-control",
					"no-store, max-age=0",
				)

				message["headers"] = list(headers.items())

			await send(message)

		await self.app(scope, receive, send_wrapper)
