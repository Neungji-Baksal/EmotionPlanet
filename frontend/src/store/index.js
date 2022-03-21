import Vue from 'vue'
import Vuex from 'vuex'
import axios from 'axios'

const session = window.sessionStorage;
const jwt = require('jsonwebtoken');

Vue.use(Vuex)
import Stomp from "webstomp-client";
import SockJS from "sockjs-client";

export default new Vuex.Store({
  state: {
    // feedActive: false,
    //검색부분
    searching: false, //검색창 활성화
    words: null, //검색창
    tagSearch: [],
    userSearch: [],
    pickSearch: [],
    tagSearchResult: [], //검색 결과
    userSearchResult: [],
    pickSearchResult: [],
    //로딩페이지
    loading: true,
    //메인 추천탭 부분
    userEmotion: null,
    recommendType: 1,
    recommendMusic: [],
    recommendMovie: [],
    recommendActivity: [],
    recommendReload: 0,
    //플레이리스트 만들기
    type:0, // 음악:0 영화:1 활동:2
    //내가 선택한 아이템
    item:null,
    feedAuthor: null,
    // 내정보
    userInfo: null,
    userFollowInfo : {
      //나를 팔로우 하는 사람(팔로워)
      userFollow :[],
      // 내가 팔로우 하는 사람(팔로잉)
      userFollowing : [],
    },
    userFeedInfo: [], //내 피드 정보
    userPickInfo: [], //내 찜목록 정보
    //피드 좋아요 목록
    feedLikesInfo:[],
    // 다른유저 정보
    searchUserNo: null, //검색할 유저 번호 저장
    searchUserInfo: null, // 검색한 유저 정보 저장
    searchUserFollowInfo : {
      followcheck : null, // 0이면 언팔 1이면 팔로우중
      waiting : null, // 1이면 대기중
      //나를 팔로우 하는 사람(팔로워)
      userFollow :[],
      // 내가 팔로우 하는 사람(팔로잉)
      userFollowing : [],
    },
    searchUserFeedInfo: [], //내 피드 정보
    searchUserPickInfo: [], //내 찜목록 정보
    followerList: null,
    followingList: null,

    planetStyles: [
      { id: 1, name: '행복행성', img: "happy.png", color: '#6BD9E8' },
      { id: 2, name: '우울행성', img: "depressed.png", color: '#2A61F0' },
      { id: 3, name: '떠돌이행성', img: "space-station.png", color: '#ABBECA' },
      { id: 4, name: '공포행성', img: "fear.png", color: '#ED5A8E' },
      { id: 5, name: '깜짝행성', img: "surprised.png", color: '#FEA95C' },
      { id: 6, name: '분노행성', img: "rage.png", color: '#FB5D38' },
      { id: 7, name: '떠돌이행성', img: "spaceship.png", color: '#FCBB74' },
    ],
    navActive: [false, false, false, false, false],
    showingNav: true,
    user: null,
    // 피드작성
    feedCreateData: [
      {descr: null, author:null, tags: []},
      {image: []},
    ],
    feedDetailNum: null,
    //이미지
    rawImg: [],
    
    // 모달 데이터
    commentSettingModalActive: false,
    logoutModalActive: false,
    userFeedSettingModalActive: false,
    profileImgChangeModalActive: false,
    loginConfirmModalActive: false,
    signupConfirmModalActive: false,
    emotionTestTooMuchPickModalActive: false,
    firstEmotionTestConfirmModalActive: false,
    emotionTestErrorActive: false,
    emotionTestPickMoreModalActive: false,
    emotionTestResultModalActive: false,
    ReturnToLoginModalActive: false,
    loginFailModalActive: false,
    signupFailModalActive1: false,
    signupFailModalActive2: false,
    commentNeedContentModalActive:false,
    moreInfoConfirmModalActive: false,
    feedUpdateActive: false,
    pickYourImageModalActive: false,
    tooMuchImagesModalActive: false,
    pickYourTagModalActive: false,
    mypagefollowingListActive: false,
    mypagefollowerListActive: false,
    userpagefollowingListActive: false,
    userpagefollowerListActive: false,
    likesListActive:false,
    addPlayListActive:false,
    addToPlayListActive:false,
    nicknameErrModalActive:false,
    pwchangeErrModalActive:false,
    pwchangeConfirmModalActive:false,
    foundEmailModalActive:false,
    foundEmail: null,
    notfoundEmailModalActive:false,
    noTelModalActive:false,
    wrongEmailModalActive:false,
    noMatchEmailModalActive:false,

  
    // 모달의 에러 메시지
    serverErrorMessage: '',
    loginErrorMessage: '',

    // 알림 부분
    alarm: [], 
    socketcount : 0, // 소켓 연결 일정시간 이상 안되면 재로그인 시키기

    // 댓글
    comments: [],
    commentsOnTwo: [],
    comment:[],
    commentNum: null,
    commentDeleted: false
  },
  mutations: {
    load(state, payload){
      state.loading = payload
    },
    navActivate: function({ navActive }, payload){
      console.log('지금 나는?', payload)
      if (payload == -1){
        navActive.forEach((ele, idx) => {
          Vue.set(navActive, idx, false)
          console.log('1차', navActive)
        })
        return 
      }
      if (payload == 0 || payload == 3){
        Vue.set(navActive, payload, !navActive[payload])
        return 
      }
      navActive.forEach((ele, idx) => {
        navActive[idx] = false
      })

      Vue.set(navActive, payload, true)
      console.log(navActive)
    },
    navActivate2: function(state, payload) {
        state.showingNav = payload
    },
    //검색부분
    updateSearch: function(state, searchWords){
      console.log(state)
      state.words = searchWords
    },

    userUpdate(state, payload){
      console.log("userUpdate 접근 =====")
      console.log(payload)
      const userdata = JSON.parse(session.getItem('userInfo')) 
      console.log(userdata)
      if (!session.getItem('userInfo')){
        session.setItem('userInfo', JSON.stringify(payload.userInfo)) //토큰값으로 들어오면 
      }
      
      // else if(typeof(payload) == 'number'){ // 감테하고 넘길때
      //   userdata.mood = payload
      //   session.setItem('userInfo', JSON.stringify(userdata))
      // } 
      
      else if (session.getItem('userInfo')){
        session.setItem('userInfo', JSON.stringify(payload.userInfo)) 
      }


      console.log('userUpdate 완료 ======' + session.getItem('userInfo'))
      state.userInfo = JSON.parse(session.getItem('userInfo')) 
      // return userdata
    },

    tokenTest(){
      console.log("test")
    },
    feedOut({ navActive }){
      Vue.set(navActive, 0, false)
    },
    // 피드작성 부분
    feedUserData: function (state, feedDto) {
      state.feedCreateData[0].author = feedDto.author
      state.feedCreateData[0].tags[0] = feedDto.tags[0]
      console.log(state.feedCreateData[0])
    },
    feedImg: function (state, imgs) {
      state.rawImg =imgs
      console.log(state.feedCreateData)
    },
    rawImg: function (state, imgs) {
      state.feedCreateData[1].image =imgs
      console.log(state.feedCreateData)
    },
    feedTag: function(state, feedtag) {
      state.feedCreateData[0].tags[1] = feedtag
      // state.feedCreateData[0].tags.push({name: `${feedtag}`, type: 0})
      // console.log(state.feedCreateData[0].tags)
    },
    feedNumberForUpdate: function(state, feedNumber) {
      state.feedDetailNum = feedNumber
      console.log(state.feedDetailNum)
    },
    // 모달부분입니다
    commentSettingModalActivate: function (state, commentNum) {
      state.commentSettingModalActive = !state.commentSettingModalActive
      state.commentNum = commentNum
      console.log(state.commentSettingModalActive, commentNum)
    },
    userFeedSettingModalActivate: function (state, payload=0) {
      state.userFeedSettingModalActive = !state.userFeedSettingModalActive
      if (payload){
        state.feedAuthor = payload
      }
      console.log(state.userFeedSettingModalActive)
    },
    logoutModalActivate: function (state) {
      state.logoutModalActive = !state.logoutModalActive
      console.log(state.logoutModalActive)
    },
    profileImgChangeModalActivate: function (state) {
      state.profileImgChangeModalActive = !state.profileImgChangeModalActive
      console.log(state.profileImgChangeModalActive)
    },
    loginConfirmModalActivate:function (state) {
      state.loginConfirmModalActive = !state.loginConfirmModalActive
      console.log(state.loginConfirmModalActive)
      // return state.loginConfirmModalActive
    },
    signupConfirmModalActivate:function (state) {
      state.signupConfirmModalActive = !state.signupConfirmModalActive
      console.log(state.signupConfirmModalActive)
    },
    emotionTestTooMuchPickModalActivate: function (state) {
      state.emotionTestTooMuchPickModalActive = !state.emotionTestTooMuchPickModalActive
      console.log(state.emotionTestTooMuchPickModalActive)
    },
    firstEmotionTestConfirmModalActivate: function (state) {
      state.firstEmotionTestConfirmModalActive = !state.firstEmotionTestConfirmModalActive
      console.log(state.firstEmotionTestConfirmModalActive)
    },
    emotionTestErrorModalActivate: function (state) {
      state.emotionTestErrorActive = !state.emotionTestErrorActive
      console.log(state.emotionTestErrorActive)
    },
    emotionTestPickMoreModalActivate: function (state) {
      state.emotionTestPickMoreModalActive = !state.emotionTestPickMoreModalActive
      console.log(state.emotionTestPickMoreModalActive)
    },
    emotionTestResultModalActivate: function (state) {
      state.emotionTestResultModalActive = !state.emotionTestResultModalActive
      console.log(state.emotionTestResultModalActive)
    },
    ReturnToLoginModalActivate: function (state) {
      state.ReturnToLoginModalActive = !state.ReturnToLoginModalActive
      console.log(state.ReturnToLoginModalActive)
    },
    loginFailModalActivate: function (state, errormessage) {
      state.loginErrorMessage = errormessage 
      state.loginFailModalActive = !state.loginFailModalActive
      console.log(state.loginFailModalActive)
    },
    signupFailModalActivate1: function (state, errormessage) {
      state.signupFailModalActive1 = !state.signupFailModalActive1
      state.serverErrorMessage = errormessage
      console.log(state.signupFailModalActive1)
    },
    signupFailModalActivate2: function (state) {
      state.signupFailModalActive2 = !state.signupFailModalActive2
      console.log(state.signupFailModalActive2)
    },
    commentNeedContentModalActivate: function (state) {
      state.commentNeedContentModalActive = !state.commentNeedContentModalActive
      console.log(state.commentNeedContentModalActive)
    },
    moreInfoConfirmModalActivate: function (state) {
      state.moreInfoConfirmModalActive = !state.moreInfoConfirmModalActive
      console.log(state.moreInfoConfirmModalActive)
    },
    //정보변경페이지 모달 3개
    nicknameErrModalActivate: function (state) {
      state.nicknameErrModalActive = !state.nicknameErrModalActive
    },
    pwchangeConfirmModalActivate: function (state) {
      state.pwchangeConfirmModalActive = !state.pwchangeConfirmModalActive
    },
    pwchangeErrModalActivate: function (state) {
      state.pwchangeErrModalActive = !state.pwchangeErrModalActive
    },
    //
    feedUpdateActivate: function (state) {
      state.feedUpdateActive = !state.feedUpdateActive
      console.log(state.feedUpdateActive)
    },
    pickYourImageModalActivate: function (state) {
      state.pickYourImageModalActive = !state.pickYourImageModalActive
      console.log(state.pickYourImageModalActive)
    },
    tooMuchImagesModalActivate: function (state) {
      state.tooMuchImagesModalActive = !state.tooMuchImagesModalActive
      console.log(state.tooMuchImagesModalActive)
    },
    pickYourTagModalActivate: function (state) {
      state.pickYourTagModalActive = !state.pickYourTagModalActive
      console.log(state.pickYourTagModalActive)
    },
    mypagefollowingListActivate: function (state, payload) {
      state.mypagefollowingListActive = !state.mypagefollowingListActive
      state.followingList = payload
    },
    mypagefollowerListActivate: function (state, payload) {
      state.mypagefollowerListActive = !state.mypagefollowerListActive
      state.followerList = payload
    },
    userpagefollowingListActivate: function (state) {
      state.userpagefollowingListActive = !state.userpagefollowingListActive
      console.log(state.userpagefollowingListActive)
    },
    userpagefollowerListActivate: function (state) {
      state.userpagefollowerListActive = !state.userpagefollowerListActive
      console.log(state.userpagefollowerListActive)
    },
    likesListActive:function(state,likesList){
      state.likesListActive=!state.likesListActive
      state.feedLikesInfo=likesList
      console.log(state.likesListActive)
    },
    addPlayListActive:function(state,sendData){
      state.addPlayListActive=!state.addPlayListActive
      state.type=sendData[0]
      state.item=sendData[1]
      console.log(state.addPlayListActive)
    },
    addToPlayListActive:function(state,sendData){
      state.addToPlayListActive=!state.addToPlayListActive
      state.pickedForderName=sendData
    },
    // 댓글
    isDelete: function (state) {
      if (state.commentNum) {
        state.commentDeleted = state.commentNum
      }
      console.log(state.commentDeleted)
    },
    //이메일찾기 페이지 모달 3개
    foundEmailModalActivate: function (state, email) {
      state.foundEmailModalActive = !state.foundEmailModalActive
      state.foundEmail = email
    },
    notfoundEmailModalActivate: function (state) {
      state.notfoundEmailModalActive = !state.notfoundEmailModalActive
    },
    noTelModalActivate: function (state) {
      state.noTelModalActive = !state.noTelModalActive
    },
    //비번찾기 페이지 모달 2개 
    wrongEmailModalActivate: function (state) {
      state.wrongEmailModalActive = !state.wrongEmailModalActive
    },
    noMatchEmailModalActivate: function (state) {
      state.noMatchEmailModalActive = !state.noMatchEmailModalActive
    },

  },
  actions: {

    //피드 좋아요 취소 부분
    deletefeedlike(state, el) { // 좋아요 취소는 피드 번호만 넘겨주기
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
    };
    let data = {
      userNo : this.state.userInfo.no,
      targetNo : el,
    };
    axios({
        method: 'delete',
        url: '/api/feeds/like',
        data: data, // post 나 put에 데이터 넣어 줄때
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {
      console.log("피드 좋아요 삭제 성공")
      this.dispatch('accessTokenRefresh', res) // store에서
      }).catch((error) => {
        console.log("피드 좋아요 삭제 실패")
        console.log(error);
      })
    },

    //피드 좋아요 부분 el = { feedno : feedno , receiver : receiver}
    addfeedlike(state, el) { // 피드 번호만 넘겨주기
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      let data = {
        userNo : this.state.userInfo.no,
        targetNo : el.feedno,
      };
      axios({
          method: 'post',
          url: '/api/feeds/like',
          data: data, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
        console.log("피드 좋아요 추가 성공")
        this.dispatch('feedlike',el)
        this.dispatch('accessTokenRefresh', res) // store에서
        }).catch((error) => {
          console.log("피드 좋아요 실패")
          console.log(error);
        })
      },

      //알림 읽기 + 7일 이후 읽은 알림 삭제
      readAlarm(state, el){
          axios({
            method: 'get',
            url: '/api/alarm/read/'+ el,
          }).then((res) => {
            console.log("알림 읽기 성공") 
            console.log(res.data)
            this.state.alarm = []
          }).catch(() => {
            console.log('알림 읽기 실패 ');
          })
        },

     // 여기는 알림 시작 --------------------------------------------------------
     follow(state, el) { //팔로우 알림 보내는 부분
      console.log("팔로우 알림");
      console.log(el)
      console.log(this.state.userInfo.no)
      if (this.stompClient && this.stompClient.connected) {
        const msg = {
          sender: this.state.userInfo.no,
          receiver: el,
          type: 1, 
        };
        this.stompClient.send(
          "/alarm/send/" + el,
          JSON.stringify(msg),
          {}
        );
      }
    },

    // let el = {
      // receiver: 00,
      // feedno: 00,
      // pickno: 00,
      // commentno: 00,
    // }
    comment(state, el) { // 댓글달면 누가 댓글달았는지 알려주는 부분
      console.log("댓글 알림");
      if (this.stompClient && this.stompClient.connected) {
        const msg = {
          sender: this.state.userInfo.no,
          receiver: el.receiver,
          feedno: el.feedno, // 여기 나중에 수정해야함
          commentno: el.commentno,
          type: 2, 
        };
        this.stompClient.send(
          "/alarm/send/" + el.receiver,
          JSON.stringify(msg),
          {}
        );
      }
    },

    feedlike(state, el) { //피드 좋아요누르면 누가 좋아요 눌렀는지 알려주는 부분
      console.log("좋아요 알림");
      if (this.stompClient && this.stompClient.connected) {
        const msg = {
          sender: this.state.userInfo.no,
          receiver: el.receiver,
          feedno: el.feedno, // 여기 나중에 수정해야함
          type: 3, 
        };
        this.stompClient.send(
          "/alarm/send/" + el.receiver,
          JSON.stringify(msg),
          {}
        );
      }
    },

    picklike(state, el) { //찜목록 좋아요누르면 누가 좋아요 눌렀는지 알려주는 부분
      console.log("좋아요 알림");
      if (this.stompClient && this.stompClient.connected) {
        const msg = {
          sender: this.state.userInfo.no,
          receiver: el.receiver,
          pickno: el.pickno, // 여기 나중에 수정해야함
          type: 4, 
        };
        this.stompClient.send(
          "/alarm/send/" + el.receiver,
          JSON.stringify(msg),
          {}
        );
      }
    },

    connect() { // 웹 소켓 연결하는 부분.
      const serverURL = "/api";
      let socket = new SockJS(serverURL);
      this.stompClient = Stomp.over(socket);
      console.log(`소켓 연결을 시도합니다. 서버 주소: ${serverURL}`);
      this.stompClient.connect(
        {},
        (frame) => {
          // 소켓 연결 성공
          this.connected = true;
          console.log("소켓 연결 성공",frame);
          // 서버의 메시지 전송 endpoint를 구독합니다.
          // 이런형태를 pub sub 구조라고 합니다.
          this.stompClient.subscribe(`/alarm/receive/${this.state.userInfo.no}`, (res) => {
            this.dispatch('alarmselect')
            const obj = JSON.parse(res.body);
            if(obj.type === 1){
              this.dispatch('userfollowdate', this.state.userInfo.no);
            }
          });
        },
        (error) => {
          // 소켓 연결 실패
          console.log("소켓 연결 실패", error);
          this.connected = false;
          this.state.socketcount++
          if(this.state.socketcount > 10){
            const authInst = window.gapi.auth2.getAuthInstance();
            console.log('signout called', authInst)
            authInst.signOut()
            .then(() => {
              // eslint-disable-next-line
              console.log('User Signed Out!!!');
              authInst.disconnect();
              session.clear();
            })
            .then(() => {
              window.location.reload()
            })
            .catch(() => alert('fail'))
            alert("서버 문제 발생")
          }
          this.dispatch('connect'); // 소켓 재연결 시도
        }
      );
    },

    // 이부분은 나중에 알림 부분에서 사용할 예정
    alarmselect(){ // 디비에 있는 알림 가져오기
      axios({
        method: 'get',
        url:'/api/alarm/' + this.state.userInfo.no,
      })
      .then((res)=>{
        console.log('알림 가져오기 성공', res)
        this.state.alarm = res.data
      })
      .catch(err=> {
        console.log('알림 가져오기 실패')
        console.log(err.response.data.message) // 서버측에서 넘어온 오류 메시지 출력.
      })
    },
    
    alarmdelete(state ,el){ // 읽은 알림 지우기=> 알림번호 넘겨주는거 생각해야함
      axios({
        method: 'delete',
        url:'/api/alarm/' + el, // 여기 알림번호 넘겨줘야한다.
      })
      .then((res)=>{
        console.log('알림 삭제 성공')
        console.log(res.data)
      })
      .catch(err=> {
        console.log('알림 삭제 실패')
        console.log(err.response.data.message) // 서버측에서 넘어온 오류 메시지 출력.
      })
    },
    // 여기는 알림 끝 -----------------------------------------------------



    //팔로우 삭제
    deletefollow(state, el) {
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      let data = {
        sender : this.state.userInfo.no,
        receiver : el,
      };
      axios({
          method: 'delete',
          url: '/api/follows',
          data: data, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
        console.log("언팔로우 성공")
        this.state.searchUserFollowInfo.followcheck = 0
        this.dispatch('accessTokenRefresh', res) // store에서
        this.dispatch('userfollowdate', el);
        this.dispatch('userfollowdate', this.state.userInfo.no);
        }).catch((error) => {
          console.log("언팔로우 실패")
          console.log(error);
        }).then(() => {
          console.log('getQSSList End!!');
        });
      },

    //팔로우 신청
    sendfollow(state, el) {
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      let data = {
        sender : this.state.userInfo.no,
        receiver : el,
      };
      axios({
          method: 'post',
          url: '/api/follows',
          data: data, // post 나 put에 데이터 넣어 줄때
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
        console.log("팔로우 성공")
        this.state.searchUserFollowInfo.followcheck = 1
        this.dispatch('accessTokenRefresh', res) // store에서
        this.dispatch('follow',el)
        this.dispatch('userfollowdate', el);
        this.dispatch('userfollowdate', this.state.userInfo.no);
        }).catch((error) => {
          console.log("팔로우 실패")
          console.log(error);
        }).then(() => {
          console.log('getQSSList End!!');
        });
      },

    // 여기는 회원 번호로 회원의 정보를 가져오는 부분입니다.
    userSelect(state, el) {
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'get',
          url: '/api/users/'+ el,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
          console.log("유저 정보 갱신 성공")
          console.log(res.data)
          this.state.searchUserInfo = res.data
          this.dispatch('accessTokenRefresh', res) // store에서
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('getQSSList End!!');
        });
      },

    // 마이페이지 or 유저 페이지 정보 가져온느 부분 입니다.
    userfollowdate(state, el) {
      let headers = {
          'at-jwt-access-token': session.getItem('at-jwt-access-token'),
          'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
        axios({
          method: 'get',
          url: '/api/follows/'+this.state.userInfo.no+"/"+el,
          headers: headers,  // 넣는거 까먹지 마세요
        }).then((res) => {
          if(this.state.userInfo.no === el){
            console.log("나의 갱신 성공")
            console.log(res.data)
            this.state.userFollowInfo.userFollow = res.data.follower
            this.state.userFollowInfo.userFollowing = res.data.following
            console.log(this.state.userFollowInfo.userFollow.length)
            console.log(this.state.userFollowInfo.userFollowing.length)
          }else{
            console.log("유저 갱신 성공")
            console.log(res.data)
            this.state.searchUserFollowInfo.userFollow = res.data.follower
            this.state.searchUserFollowInfo.userFollowing = res.data.following
            this.state.searchUserFollowInfo.followcheck = res.data.followResult
            this.state.searchUserFollowInfo.waiting = res.data.waition
          }
          this.dispatch('accessTokenRefresh', res) // store에서
        }).catch((error) => {
          console.log(error);
        }).then(() => {
          console.log('getQSSList End!!');
        });
      },
    // 마이페이지랑 유저페이지 피드&찜목록 정보 가져오는 부분  
    searchUserFeed(state, el) {
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
        method: 'get',
        url: '/api/feeds/my/' + el,
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {
        if (el === this.state.userInfo.no) {
          this.state.userFeedInfo = res.data
        }
        else {
          this.state.searchUserFeedInfo = res.data
        }
        console.log("피드 가져오기 성공")
        console.log(res.data)
        this.dispatch('accessTokenRefresh', res)
      }).catch((error) => {
        console.log("피드 가져오기 실패")
        console.log(error);
      })
    },

    //여기 검색부분입니다
    // 검색창에 넣은 단어를 포함하는 피드 개수를 가져옴
    searchTag() {
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
        method: 'get',
        url:'/api/searchs/byTag/' + this.state.words,
        headers: headers,
      }).then(res => {
        this.dispatch('accessTokenRefresh', res)
        this.state.tagSearch = res.data
        console.log('태그 있음')
      })
      .catch(()=> {
        console.log('태그 없음')
        this.state.tagSearch = []
      })
    },
    // 클릭하는 태그의 피드 정보 전체를 가져옴
    searchTagSearch(state, el) {
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
        method: 'get',
        url: '/api/searchs/byTag/feed/'+this.state.userInfo.no + '/' + el,
        headers: headers,  // 넣는거 까먹지 마세요
      }).then((res) => {
        console.log("태그 피드 검색 성공")
        console.log(res.data)
        this.state.tagSearchResult = res.data
        this.state.tagSearch = []
        this.dispatch('accessTokenRefresh', res)
      }).catch((error) => {
        console.log("태그 피드 검색 실패")
        console.log(error);
      })
    },

    searchUser() {
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
      };
      axios({
        method: 'get',
        url:'/api/searchs/byNickName/' + this.state.words,
        headers: headers,
      })
      .then((res)=>{
        this.dispatch('accessTokenRefresh', res)
        this.state.userSearch = res.data
        console.log('유저 있음')
      })
      .catch(()=> {
        console.log('유저 없음')
        this.state.userSearch = []
      })
    },

    //검색 끝 추천탭 시작입니다

    accessTokenRefresh({commit}, res) {
      console.log("accesstoken : " + res.headers)
      if(res.headers['at-jwt-access-token'] != session.getItem('at-jwt-access-token')){
        session.setItem('at-jwt-access-token', "");
        session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
        console.log("Access Token을 교체합니다!!!")
      }
      commit('tokenTest')
    },

    allTokenRefreshOnUserInfo({commit},res){ // 유저 정보 갱신할때 사용
      console.log("allTokenRefreshOnUserInfo : " + res.headers['at-jwt-access-token'])
      session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
      const decodeAccessToken = jwt.decode(res.headers['at-jwt-access-token']);
      console.log('decodeAccessToken data', decodeAccessToken);
      commit('userUpdate', decodeAccessToken)
    },

    allTokenRefresh({commit},res){
      console.log("alltoken : " + res.headers)
      session.setItem('at-jwt-access-token', res.headers['at-jwt-access-token']);
      session.setItem('at-jwt-refresh-token', res.headers['at-jwt-refresh-token']);

      const decodeAccessToken = jwt.decode(res.headers['at-jwt-access-token']);
      console.log('decodeAccessToken data', decodeAccessToken);
      commit('userUpdate', decodeAccessToken)

      return new Promise((resolve) => {
        resolve(true)
      })
    },

    //유저정보 수정부분
    updateuser(state ,el) {
      const body = {
        no: this.state.userInfo.no,
        nickname: this.state.userInfo.nickname,
        intro: this.state.userInfo.intro,
        pw: el, //null 해야지 데이터 안넘어감
        publish: this.state.userInfo.publish,
      };
      let headers = {
        'at-jwt-access-token': session.getItem('at-jwt-access-token'),
        'at-jwt-refresh-token': session.getItem('at-jwt-refresh-token'),
        };
      axios({
        method: "put",
        url: "/api/users/update",
        data: body,
        headers: headers,
      })
        .then((res) => {
          console.log(body)
          console.log("업데이트 성공")
          console.log(res);
          this.dispatch('allTokenRefreshOnUserInfo', res)
          // console.log(this.state.userInfo)
          // location.reload()
        })
        .catch((err) => {
          console.log("업데이트 실패")
          console.log(err);
        });
    },
  },
  modules: {
    
  }
})