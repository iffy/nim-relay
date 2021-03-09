import os
import logging

if os.getEnv("SHOW_LOGS") != "":
  var L = newConsoleLogger()
  addHandler(L)
else:
  echo "set SHOW_LOGS=something to see logs"
