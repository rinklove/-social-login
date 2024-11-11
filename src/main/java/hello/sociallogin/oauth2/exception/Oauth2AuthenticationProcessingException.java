package hello.sociallogin.oauth2.exception;


import org.springframework.security.core.AuthenticationException;

public class Oauth2AuthenticationProcessingException extends AuthenticationException {

    public Oauth2AuthenticationProcessingException(String msg) {
        super(msg);
    }
}
