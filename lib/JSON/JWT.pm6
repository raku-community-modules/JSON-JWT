use JSON::Fast;
use MIME::Base64;
use OpenSSL::Digest;
use OpenSSL::RSATools;
use Digest::HMAC;

class JSON::JWT {
    multi method decode($jwt, :$alg where 'none') {
        my %pack = self._unpack($jwt);
        if %pack<header><alg> ne 'none' {
            die "Header lists signature type != 'none' ("~%pack<header><alg>~")";
        }
        if %pack<signature> {
            die "Signature exists with signature type = 'none'";
        }

        return %pack<body>;
    }
    multi method decode($jwt, :$alg where 'HS256', :$secret!) {
        my %pack = self._unpack($jwt);
        if %pack<header><alg> ne 'HS256' {
            die "Header lists signature type != 'HS256' ("~%pack<header><alg>~")";
        }
        if !%pack<signature> {
            die "No signature found.";
        }
        my $sign = hmac($secret, %pack<sigblob>, &sha256);
        if $sign ne %pack<signature> { # XXX secure compare? XXX #
            die "Signature does not match.";
        }
        
        return %pack<body>;
    }
    multi method decode($jwt, :$alg where 'RS256', :$pem!) {
        my %pack = self._unpack($jwt);
        if %pack<header><alg> ne 'RS256' {
            die "Header lists signature type != 'RS256' ("~%pack<header><alg>~")";
        }
        if !%pack<signature> {
            die "No signature found.";
        }
        my $key = OpenSSL::RSAKey.new(:public-pem($pem));
        if !$key.verify(%pack<sigblob>, %pack<signature>, :sha256) {
            die "Signature verify failed.";
        }

        return %pack<body>;
    }

    method decode-noverify($jwt) {
        my %pack = self._unpack($jwt);
        return %pack<body>;
    }

    method _unpack($jwt) {
        my @parts = $jwt.split('.');
        if @parts < 2 || @parts > 3 {
            die "JWT does not have 2 or 3 parts; cannot unpack.";
        }

        my %pack;
        %pack<sigblob> = join('.', @parts[0], @parts[1]).encode('ascii');
        %pack<signature> = MIME::Base64.decode(@parts[2]) if @parts[2];
        %pack<header> = from-json(MIME::Base64.decode-str(@parts[0]));
        %pack<body> = from-json(MIME::Base64.decode-str(@parts[1]));

        if %pack<header><typ> ne 'JWT' {
            die "Not a JWT";
        }

        %pack;
    }
}
