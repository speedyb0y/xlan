savedcmd_/build/xlan/xnic.mod := printf '%s\n'   xnic.o | awk '!x[$$0]++ { print("/build/xlan/"$$0) }' > /build/xlan/xnic.mod
