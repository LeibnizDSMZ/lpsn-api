

Sys.setenv(
  # try settings this to "" or "0" once public API is ready
  DSMZ_KEYCLOAK_INTERNAL = "1",
  # this may assist in debugging
  DSMZ_API_VERBOSE = "1",
  # for running the examples these must be read from the system
  # environment -- we cannot hardcode them into the R package
  DSMZ_API_USER = "julia.koblitz@dsmz.de",
  DSMZ_API_PASSWORD = "4GHjHAyp"
)

library(LPSN) # which must be installed beforehand, of course

example(fetch) # the examples also act as tests

traceback()

