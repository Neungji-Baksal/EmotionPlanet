# **EmotionPlanet**

## 프로젝트 개요

현대 사회인들이 자신의 감정을 표출하기 어려워하고 

그래서 저희는 감정을 표현하고 공유하는 공간이 있으면 좋겠다고 생각하여

이모션 플래닛을 제작하게 되었습니다.



**저는 여기서 백엔드 서비스 개발과 배포를 맡았습니다.**

<hr/>

## 배포환경

[![아키텍처](https://i.ibb.co/ZHNhK0X/image.png)]()

(사진 : 아키텍처)

깃랩에 코드를 Merge하면 젠킨스가 웹훅을 통해 코드를 인스턴스로 가져오고 docker-compose가 

DockerFile을 배포하였습니다. 그러면 NGINX가 80포트로 들어오는 모든 요청에 대해 '/' 로 시작하면 443 프론트 서비스로

'/api'로 시작하면 8443 백엔드 서비스로 리버스 프록시 해줍니다. DB는 AWS RDS를 사용하려 했으나

비용이 발생해서 SSAFY에서 제공해준 인스턴스에 로드했고 이미지 파일은 AWS S3 클라우드를 사용하여 

배포했습니다.

<hr/>

## Jenkins + Docker 배포 (CI/CD)

- Docker 환경 설정

  - 필수패키지

    ```bash
    sudo apt-get install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
    ```

  - GPG Key 인증

    ```bash
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    ```

  - docker repository 등록

    ```bash
    sudo add-apt-repository \
    "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) \
    stable"
    ```

  - docker 설치

    ```bash
    sudo apt-get update && sudo apt-get install docker-ce docker-ce-cli containerd.io
    ```

  - docker 설치(버전) 확인

    ```bash
    docker -v
    ```

- Jenkins 환경 설정

  - 도커 내부 9090포트에 설치하기

    ```bash
    sudo docker run -d --name jenkins -u root --privileged \
    -p '9090:8080' \
    -v '/home/ubuntu/docker-volume/jenkins:/var/jenkins_home' \
    -v '/var/run/docker.sock:/var/run/docker.sock' \
    -v '/usr/bin/docker:/usr/bin/docker' \
    jenkins/jenkins
    
    //privileged : 도커 컨테이너 내부에서 host 시스템에 접근 권한 주는 옵션
    ```

  - Jenkins 컨테이너 내부 docker-compose 설치

    ```bash
    # docker 컨테이너 내부 bash 접속
    docker exec -it jenkins bash
    
    # 버전은 자신의 환경에 맞춰서 설치하는 것을 추천
    curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    
    # docker-compose 사용 권한 부여
    chmod +x /usr/local/bin/docker-compose
    
    # 설치(버전) 확인
    docker-compose -v
    ```

  - Jenkins 접속하기

    - 도메인:9090 으로 접속
    - /home/ubuntu/docker-volume/jenkins/secrets/initialAdminPassword 여기서 암호 확인 후 접속
    - Install suggested plugins 선택
    - 계정 생성

  - Credential

    - Username / Password : 깃 혹은 깃랩 계정

    - ID : Credential 식별자

    - Description : Credential 설명 (그냥 아무거나)

    - Error

      나 같은 경우는 배포 할 때 CredentialId를 찾을 수 없다는 에러가 났다. 이를 해결 하려면

      [![credential](https://i.ibb.co/qyLy5fT/11.png)]()

      하단의 Jenkins 페이지 내에서 Credential을 생성 해야 한다.		

      ​	

  - WEBHOOK

    나는 SSAFY에서 사용하는 GITLAB을 사용했기 때문에 GITLAB 플러그인을 설치하여 사용했다.

    ```tex
    #GitLab 플러그인 설치
    
    Jenkins 관리 -> 플러그인 관리 -> 설치 가능 - GitLab 설치 및 재시작
    
    #PipeLine 생성
    
    새로운 Item -> PipeLine
    
    #Jenkins - GitLab Webhooks Secret Token 생성
    
    구성 -> Build when a change is pushed to GitLab. GitLab webhook(URL) 체크 박스 체크 -> 고급 버튼 -> Secret Token
    
    #GitLab - WebHook
    
    Settings - Webhooks ->
    
    URL : 상단에 설명한 체크박스 URL
    Secret token : 상단에 설명한 Secret Token
    Push events : 업로드할 브랜치 이름
    
    Add webhook -> Test - push Events ->HTTP 200 확인
    ```

    

  - PipeLine

    Definition - PipeLine script

    Script 입력

    ```bash
    node {
        stage ('clone') {
            git branch: 'clone할 브랜치', credentialsId: 'credential 식별자', url: 'Gitlab 저장소 Url'
        }
        stage ('gradle build') {
    		// Gradle 기준
            dir('경로'){ // 경로는 build.gradle이 위치한 곳 / 예시) ('backend/EmotionPlanet')
                sh 'chmod +x gradlew'
                sh './gradlew build'
            } 
        }
    
        stage ('docker build') {
            sh 'docker-compose down --rmi all' 
    				sh 'docker-compose up -d --build' 
    				sh 'docker rmi $(docker images -f "dangling=true" -q)'
        } 
    }
    ```

    

- Docker 및 Ubuntu 설정

  - SSL 인증 (https 사용을 위해 설정)

    ```bash
    # letsencrypt 설치하기
    sudo apt-get update
    sudo apt-get install letsencrypt
    
    # 인증서 발급
    sudo letsencrypt certonly --standalone -d '도메인'
    
    # 비밀번호, 이메일 입력 및 안내 사항에 동의 후 진행
    
    # root 계정 로그인
    sudo su
    
    # 인증서 위치 폴더 이동
    cd /etc/letsencrypt/live/도메인
    
    # pem을 PKCS12 형식으로 변경
    openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out key.p12 -name airpageserver -CAfile chain.pem -caname root
    
    
    # 인증서 복사
    # 인증서 보관 폴더를 미리 생성하기.
    
    sudo cp fullchain.pem /home/ubuntu/docker-volume/ssl-copy
    sudo cp privkey.pem /home/ubuntu/docker-volume/ssl-copy
    sudo cp key.p12 /home/ubuntu/docker-volume/ssl-copy
    ```

    

  - 백엔드 Properties

    ```tex
    # application-prod.properties
    # SSL 설정
    
    server.port=8443
    server.ssl.enabled=true
    server.ssl.key-store-type=PKCS12
    server.ssl.key-store=/root/key.p12
    server.ssl.key-store-password=#인증서 비밀번호
    ```

  

  - Docker-compose

    ```bash
    # 프로젝트 Root 폴더
    version: '3.2'
    
    services: 
      frontend:
        image: frontend-vue
        build:
          context: frontend/
          dockerfile: Dockerfile
        ports:
          - "80:80"
          - "443:443" 
        # [인증서 파일 저장 경로]:/var/www/html
        volumes:
          - /home/ubuntu/docker-volume/ssl-copy:/var/www/html
        container_name: "frontend"
      
      backend:
        image: backend-spring
        build:
          context: backend/
          dockerfile: Dockerfile
        ports:
          - "8443:8443"  
    	# [인증서 파일 저장 경로]:/root 
        volumes:
          - /home/ubuntu/docker-volume/ssl-copy:/root
        container_name: "backend"
    ```

    

  - 프론트 Docker

    ```bash
    # frontend/Dockerfile
    
    # 버전은 사용자 환경에 맞춰서
    FROM node:14 as build-stage
    WORKDIR /app
    ADD . .
    RUN npm install
    RUN npm run build
    
    
    FROM nginx:stable-alpine as production-stage
    COPY  ./nginx.conf /etc/nginx/conf.d/default.conf
    COPY --from=build-stage /app/dist /usr/share/nginx/html
    CMD ["nginx", "-g", "daemon off;"]
    
    ```

    

  - nginx.conf

    ```bash
    
    server {
    	listen 80 default_server;
    	listen [::]:80 default_server;
    
    	access_log /var/log/nginx/access.log;
    	error_log /var/log/nginx/error.log;
    
    	# server_name 도메인;
    	server_name 도메인;
    
     // '/'로 url이 시작 하면 프론트 
    	location / {
        		alias /usr/share/nginx/html;
        		try_files $uri $uri/ /index.html;
        		return 301 https://$server_name$request_uri;
    	}
    
    }
    server {
    	listen 443 ssl;
    	listen [::]:443 ssl;
    	 
    	# server_name 도메인;
    	server_name 도메인;
    
    	ssl_certificate /var/www/html/fullchain.pem;
    	ssl_certificate_key /var/www/html/privkey.pem;
    
    	root /usr/share/nginx/html;
    	index index.html;
    
    	// '/'로 url이 시작 하면 프론트 
    
    	location / {
    		try_files $uri $uri/ /index.html;
    	}
    
    	// '/api'로 url이 시작 하면 백엔드
    	location /api {
    		proxy_pass 도메인;
    		proxy_http_version 1.1;
    		proxy_set_header Connection "";
    		proxy_set_header Host $host;
    		proxy_set_header X-Real-IP $remote_addr;
    		proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    		proxy_set_header X-Forwarded-Proto $scheme;
    		proxy_set_header X-Forwarded-Host $host;
    		proxy_set_header X-Forwarded-Port $server_port;
    
    	}
    }
    
    ```

    

  - 백엔드 Docker

    ```bash
    # backend/Dockerfile
    # 버전은 사용자 환경에 맞춰서
    FROM openjdk:8-jdk-alpine
    
    # jar 파일 경로
    COPY ./build/libs/EmotionPlanet-0.0.1-SNAPSHOT.jar app.jar
    
    # 배포용 properties 실행 명령어
    ENTRYPOINT ["java","-jar","app.jar","--spring.config.name=application-prod"]
    ```

    

  - Error

    - application-prod.properties 에러

      나 같은 경우 아무리 해도 적용이 되지 않아 그냥 application.properties 파일에 prod 코드를 추가해서 사용했다

    - docker 배포 에러

      80포트를 끄지 않으면 오류 발생 80포트는 아파치나,  NGINX가 주로 켜져 있다. 우리는 80포트가 docker-compose로 인해 로드된 컨테이너가 실행 되어야 한다.
      
      

<hr/>

## 사용 기술

### JWT + OAUTH (Vue.js And Spring Boot)

<hr/>

#### OAUTH 

- 구글 로그인

  - 구글 클라우드 설정

    구글 클라우드에서 OAUTH 정보 등록을 한 뒤 clientId를 발급받아야 한다. 간단히 검색만 해도 많은 블로그들이 정보를 제공한다.

    

  - Spring boot 코드

    @Service

    ```java
    import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
    import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
    import com.google.api.client.http.javanet.NetHttpTransport;
    import com.google.api.client.json.JsonFactory;
    import com.google.api.client.json.gson.GsonFactory;
    import com.google.gson.*;
    import com.ssafy.project.EmotionPlanet.Dao.UserDao;
    import com.ssafy.project.EmotionPlanet.Dto.UserDto;
    import com.ssafy.project.EmotionPlanet.Dto.UserSecretDto;
    import com.ssafy.project.EmotionPlanet.Service.UserService;
    import org.json.simple.JSONObject;
    import org.json.simple.parser.JSONParser;
    import org.json.simple.parser.ParseException;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.beans.factory.annotation.Value;
    import org.springframework.context.annotation.Lazy;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.stereotype.Service;
    
    import java.io.*;
    import java.net.HttpURLConnection;
    import java.net.URL;
    import java.security.GeneralSecurityException;
    import java.util.Arrays;
    import java.util.Collections;
    import java.util.HashMap;
    
    @Service
    public class PrincipalOauth2UserService {
    
        @Autowired
        UserDao userDao;
    
        // 비밀번호 인코딩
        private final BCryptPasswordEncoder bCryptPasswordEncoder;
        PrincipalOauth2UserService(@Lazy BCryptPasswordEncoder bCryptPasswordEncoder){
            this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        }
    
        private final NetHttpTransport transport = new NetHttpTransport();
        private final JsonFactory jsonFactory = new GsonFactory();
    
        private final String clientId = "자신의 clientId 보통 yml이나 env를 사용하는 것이 좋음";
    
        public UserDto tokenVerify(String idToken) {
    
            System.out.println("idToken : " + clientId);
    
            GoogleIdTokenVerifier gitVerifier = new GoogleIdTokenVerifier.Builder(transport, jsonFactory)
                    .setIssuers(Arrays.asList("https://accounts.google.com", "accounts.google.com"))
                    .setAudience(Collections.singletonList(clientId))
                    .build();
    
            GoogleIdToken git = null;
    
            try {
                git = gitVerifier.verify(idToken);
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            }
    
            UserDto user = new UserDto();
            if (git == null) {
                System.out.println("Google ID Token is invalid");
            }else {
                // 구글에서 제공받은 정보
                GoogleIdToken.Payload payload = git.getPayload();
    
                // 여기서 자신이 필요한 정보를 추출해서 사용한다.
                String userId = payload.getSubject();
                System.out.println("User ID: " + userId);
                String email = payload.getEmail();
                boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());
                String name = (String) payload.get("sub");
                String pictureUrl = (String) payload.get("picture");
                String pw = bCryptPasswordEncoder.encode("security");
    
                user.setEmail(email);
                user.setNickname(name);
                user.setProfileImg(pictureUrl);
                user.setPw(pw);
            }
            return user;
        }
    
        // 회원 등록은 자신이 개발한 것에 맞춰 주면 됨
        public int insertUser(UserDto userDto) {
            if (userDao.duplicateEmail(userDto.getEmail()) == 0) {
                int result = userDao.userRegister(userDto);
                return result;
            } else {
                return 1;
            }
        }
    
    }
    
    ```


    @Controller

    ```java
     @RequestMapping(value = "/login/oauth/google", method = RequestMethod.POST)
        public ResponseEntity<?> tokenVerify(String idToken){
            System.out.println("RequestBody value : " + idToken);
            UserDto user =  principalOauth2UserService.tokenVerify(idToken);
            HttpHeaders res = new HttpHeaders();
            if (user.getEmail() != null) {
                // 첫 로그인시 회원가입 그렇지 않으면 통과
                principalOauth2UserService.insertUser(user);
                
                // 가입된 유저 정보
                user = userService.userSelectByEmail(user.getEmail());
            }
    
            // 유저 정보 반환 해보기
            return ResponseEntity.ok().headers(res).body(user);
        }
    ```

    

  - Vue 코드

    public/index.html

    ```js
    # 아래 코드를 추가
    <script src="https://accounts.google.com/gsi/client" async defer></script>
    ```

    

    main.js

    ```js
    # npm install vue-google-oauth2
    # 아래 코드를 추가
    
    import GAuth from 'vue-google-oauth2'
    
    const gauthOption = {
      clientId: '발급받은 cliendId',
      scope: 'profile email',
      prompt: 'select_account'
    }
    Vue.use(GAuth, gauthOption)
    ```

    

    Login.vue

    ```js
    
            // 자신이 만든 구글 로그인 버튼 클릭시 handleClickSignIn() 메소드 실행
            async handleClickSignIn() {
                try {
                    const googleUser = await this.$gAuth.signIn();
                    if (!googleUser) {
                        return null;
                    }
                    console.log("googleUser", googleUser);
                    console.log("getId", googleUser.getId());
                    console.log("getBasicProfile", googleUser.getBasicProfile());
                    console.log("getAuthResponse", googleUser.getAuthResponse());
                    console.log(
                        "getAuthResponse",
                        this.$gAuth.GoogleAuth.currentUser.get().getAuthResponse()
                    );
                    this.isSignIn = this.$gAuth.isAuthorized;
                    this.onSuccess(googleUser)
                } catch (error) {
                    //on fail do something
                    this.onFailure(error)
                }
            },
            onSuccess(googleUser) {
                // eslint-disable-next-line
                console.log(googleUser);
                this.googleUser = googleUser;
                this.tokenVerify()
            },
            onFailure(error) {
                // eslint-disable-next-line
                console.log(error);
            },
            
    	    // google 로그인 후 google api가 제공해준 토큰을 백엔드로 넘겨줌
            tokenVerify() {
                const url = '/api/login/outh/google'; // 자신 백엔드 서비스 url
                const params = new URLSearchParams();
                params.append('idToken', this.googleUser.wc.id_token);
                console.log(params)
                axios.post(url, params).then((res) => {
                    alert("로그인 성공")
                    console.log("res : " + res)
                    this.$router.push('라우팅 할 곳')
                }).catch((error) => {
                    console.log(error);
                })
            },            
    ```

    

- 카카오 로그인

  

#### JWT

- JWT Code

  - Spring boot 코드

    @Interceptor

    ```java
    import com.google.gson.Gson;
    import com.ssafy.project.EmotionPlanet.Dto.TokenDto;
    import com.ssafy.project.EmotionPlanet.Dto.UserDto;
    import com.ssafy.project.EmotionPlanet.Dto.UserRequestDto;
    import com.ssafy.project.EmotionPlanet.Service.UserService;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.stereotype.Component;
    import org.springframework.web.servlet.HandlerInterceptor;
    
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    
    @Component
    public class JwtInterceptor implements HandlerInterceptor {
    
        @Autowired
        JwtService jwtService;
    
        @Autowired
        UserService userService;
    
        @Override
        public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
                throws Exception {
    
            System.out.println("####### Interceptor preHandle Start!!!");
    
            // 엑세스 토큰과 리프레시 토큰을 헤더에서 가져온다
            String atJwtToken = request.getHeader("at-jwt-access-token");
            String atJwtRefreshToken = request.getHeader("at-jwt-refresh-token");
     
            System.out.println("at-jwt-access-token : " + atJwtToken);
            System.out.println("at-jwt-refresh-token : " + atJwtRefreshToken);
            System.out.println("request method : " + request.getMethod());
            System.out.println("request URI : " + request.getRequestURI());
    
            //OPTIONS 메소드는 그냥 통과 시켜버린다.
            if ("OPTIONS".equals(request.getMethod())) {
                System.out.println("request method is OPTIONS!!");
                return true;
            }
    
            // 토큰 검증 토큰 검증이 완료되면. 백엔드 서비스 시작
            if(atJwtRefreshToken == null) {
                if(atJwtToken != null && atJwtToken.length() > 0) {
                    if(jwtService.validate(atJwtToken)) return true;
                    else throw new IllegalArgumentException("Access Token Error!!!");
                }else {
                    throw new IllegalArgumentException("No Access Token!!!");
                }
            }else {
                System.out.println("check : pass" );
                if(jwtService.validate(atJwtRefreshToken)) {
                    String accessTokenDecode = jwtService.decode(atJwtToken);
                    System.out.println("accessDto : " + accessTokenDecode);
                    Gson gson = new Gson();
                    UserRequestDto jwtPayload = gson.fromJson(accessTokenDecode, UserRequestDto.class);
    
                    String refreshTokenInDBMS = userService.selectRefreshToken(jwtPayload.getUserInfo().getEmail());
    
                    if(refreshTokenInDBMS.equals(atJwtRefreshToken)) {
                        System.out.println("일치합니다!!!");
                        String accessJws = jwtService.createAccess(jwtPayload.getUserInfo().getEmail());
                        response.addHeader("at-jwt-access-token", accessJws);
    
                    }else {
                        throw new IllegalArgumentException("Refresh Token Error!!! ND");
                    }
                    return true;
                }else {
                    throw new IllegalArgumentException("Refresh Token Error!!! NN");
                }
            }
        }
    
    }
    ```

    

  - 





![image-20220321230327584](https://i.ibb.co/7vTL93L/image-20220321230327584.png).

(사진 : 서비스 흐름 도식화)

소셜 로그인을 하면 각각의 API가 토큰을 반환하고 그 토큰을 검증 후 구글과 카카오가 제공해준 



<hr/>











