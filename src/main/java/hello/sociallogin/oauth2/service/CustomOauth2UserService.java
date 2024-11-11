package hello.sociallogin.oauth2.service;

import hello.sociallogin.oauth2.exception.Oauth2AuthenticationProcessingException;
import hello.sociallogin.oauth2.user.Oauth2UserInfo;
import hello.sociallogin.oauth2.user.Oauth2UserInfoFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOauth2UserService extends DefaultOAuth2UserService {

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        log.info("oAuth2UserRequest = {}", oAuth2UserRequest);
        log.info("oAuth2User = {}", oAuth2User);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            // Throwing an instance of AuthenticationException will trigger the OAuth2AuthenticationFailureHandler
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {

        String registrationId = userRequest.getClientRegistration()
                .getRegistrationId();
        log.info("registrationId = {}", registrationId);
        String accessToken = userRequest.getAccessToken().getTokenValue();
        log.info("accessToken = {}", accessToken);

        Oauth2UserInfo oAuth2UserInfo = Oauth2UserInfoFactory.getOAuth2UserInfo(registrationId,
                accessToken,
                oAuth2User.getAttributes());

        // OAuth2UserInfo field value validation
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new Oauth2AuthenticationProcessingException("Email not found from OAuth2 provider");
        }

        return new Oauth2UserPrincipal(oAuth2UserInfo);
    }
}
