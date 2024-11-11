package hello.sociallogin.oauth2.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum Oauth2Provider {
    GOOGLE("google"),
    NAVER("naver"),
    KAKAO("kakao")
    ;

    private final String registrationId;
}
