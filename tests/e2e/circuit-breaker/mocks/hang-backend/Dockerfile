FROM alpine:3.20
RUN apk add --no-cache socat
EXPOSE 80
# Accept TCP on :80, redirect bytes to /dev/null forever — never replies.
# Forks per connection so multiple test runs do not block each other.
CMD ["socat", "-d", "TCP-LISTEN:80,reuseaddr,fork", "EXEC:/bin/sleep 600"]
