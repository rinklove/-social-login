package hello.sociallogin.oauth2.user;

import hello.sociallogin.oauth2.exception.Oauth2AuthenticationProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class Oauth2UnlinkManager {

    private final GoogleOauth2UserUnlink googleOAuth2UserUnlink;
    private final KakaoOauth2UserUnlink kakaoOAuth2UserUnlink;
    private final NaverOauth2UserUnlink naverOAuth2UserUnlink;

    public void unlink(Oauth2Provider provider, String accessToken) {
        if (Oauth2Provider.GOOGLE.equals(provider)) {
            googleOAuth2UserUnlink.unlink(accessToken);
        } else if (Oauth2Provider.NAVER.equals(provider)) {
            naverOAuth2UserUnlink.unlink(accessToken);
        } else if (Oauth2Provider.KAKAO.equals(provider)) {
            kakaoOAuth2UserUnlink.unlink(accessToken);
        } else {
            throw new Oauth2AuthenticationProcessingException(
                    "Unlink with " + provider.getRegistrationId() + " is not supported");
        }
    }
}
