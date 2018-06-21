FROM alpine:3.7
ADD identity-scale-test /
ENTRYPOINT ["./identity-scale-test"]
