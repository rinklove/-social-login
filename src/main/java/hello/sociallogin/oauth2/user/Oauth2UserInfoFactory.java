package hello.sociallogin.oauth2.user;

import hello.sociallogin.oauth2.exception.Oauth2AuthenticationProcessingException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.util.Map;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class Oauth2UserInfoFactory {

    public static Oauth2UserInfo getOAuth2UserInfo(String registrationId,
                                                   String accessToken,
                                                   Map<String, Object> attributes) {
        if (Oauth2Provider.GOOGLE.getRegistrationId().equals(registrationId)) {
            return new GoogleOauth2UserInfo(accessToken, attributes);
        } else if (Oauth2Provider.NAVER.getRegistrationId().equals(registrationId)) {
            return new NaverOauth2UserInfo(accessToken, attributes);
        } else if (Oauth2Provider.KAKAO.getRegistrationId().equals(registrationId)) {
            return new KakaoOauth2UserInfo(accessToken, attributes);
        } else {
            throw new Oauth2AuthenticationProcessingException("Login with " + registrationId + " is not supported");
        }
    }
}
