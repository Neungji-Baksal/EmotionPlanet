<template>
  <div id="app">
    <loading v-if="loading"/>
    <navigation v-if="showingNav" />
    <create v-if="navActive[0]" />
    <router-view :key="$route.path" />
    <!-- 모달창 -->
    <logout-modal v-if="logoutModalActive" />
    <user-feed-setting v-if="userFeedSettingModalActive" />
    <comment-setting v-if="commentSettingModalActive" />
    <profile-img-change v-if="profileImgChangeModalActive" />
    <login-confirm v-if="loginConfirmModalActive" />
    <signup-confirm v-if="signupConfirmModalActive" />
    <emotion-test-too-much-pick v-if="emotionTestTooMuchPickModalActive" />
    <first-emotion-test-confirm v-if="firstEmotionTestConfirmModalActive" />
    <emotion-test-error v-if="emotionTestErrorActive" />
    <emotion-test-pick-more v-if="emotionTestPickMoreModalActive" />
    <emotion-test-result v-if="emotionTestResultModalActive" />
    <return-to-login v-if="ReturnToLoginModalActive" />
    <login-fail v-if="loginFailModalActive" />
    <signup-fail v-if="signupFailModalActive1" />
    <signup-fail-password-error v-if="signupFailModalActive2" />
    <comment-need-content v-if="commentNeedContentModalActive" />
    <more-info-confirm v-if="moreInfoConfirmModalActive" />
    <more-info-error v-if="signupFailModalActive1" />
    <update v-if="feedUpdateActive" />
    <pick-your-image v-if="pickYourImageModalActive" />
    <too-much-images-modal v-if="tooMuchImagesModalActive" />
    <pick-your-tag v-if="pickYourTagModalActive" />
    <mypage-follower-list v-if="mypagefollowerListActive" />
    <mypage-following-list v-if="mypagefollowingListActive" />
    <nickname-err v-if="nicknameErrModalActive"/>
    <pwchange-confirm v-if="pwchangeConfirmModalActive"/>
    <pwchange-err v-if="pwchangeErrModalActive"/>
    <!-- 팔로우 -->
    <userpage-follower-list v-if="userpagefollowerListActive" />
    <userpage-following-list v-if="userpagefollowingListActive" />
    <likes-list v-if="likesListActive"/>
    <add-play-list v-if="addPlayListActive"/>
    <add-to-play-list v-if="addToPlayListActive"/>
    <!-- 이메일 -->
    <found-email v-if="foundEmailModalActive"/>
    <notfound-email v-if="notfoundEmailModalActive"/>
    <no-tel v-if="noTelModalActive"/>
    <!-- 비밀번호찾기 -->
    <wrong-email v-if="wrongEmailModalActive"/>
    <no-match-email v-if="noMatchEmailModalActive"/>


  </div>
</template>

<script>
import Loading from '@/views/Loading'
import Create from '@/views/Create'
import Update from '@/views/Update'
import Navigation from '@/components/Navigation'
// 모달창
//// 세팅
import UserFeedSetting from '@/components/Modal/SettingModal/UserFeedSetting.vue'
import CommentSetting from '@/components/Modal/SettingModal/CommentSetting.vue'
//// 로그인과 로그아웃
import LoginConfirm from '@/components/Modal/LoginLogoutModal/LoginConfirm.vue'
import LogoutModal from '@/components/Modal/LoginLogoutModal/LogoutModal.vue'
import LoginFail from '@/components/Modal/LoginLogoutModal/LoginFail.vue'
import ReturnToLogin from '@/components/Modal/LoginLogoutModal/ReturnToLogin.vue'
//// 회원가입
import SignupFail from '@/components/Modal/SignupModal/SignupFail.vue'
import SignupFailPasswordError from '@/components/Modal/SignupModal/SignupFailPasswordError.vue'
import SignupConfirm from '@/components/Modal/SignupModal/SignupConfirm.vue'
import MoreInfoConfirm from '@/components/Modal/SignupModal/MoreInfoConfirm.vue'
import MoreInfoError from '@/components/Modal/SignupModal/MoreInfoError.vue'
//// 감정테스트
import EmotionTestTooMuchPick from '@/components/Modal/EmotionTestModal/EmotionTestTooMuchPick.vue'
import FirstEmotionTestConfirm from '@/components/Modal/EmotionTestModal/FirstEmotionTestConfirm.vue'
import EmotionTestError from '@/components/Modal/EmotionTestModal/EmotionTestError.vue'
import EmotionTestPickMore from '@/components/Modal/EmotionTestModal/EmotionTestPickMore.vue'
import EmotionTestResult from '@/components/Modal/EmotionTestModal/EmotionTestResult.vue'
//// 피드 관련
import PickYourImage from '@/components/Modal/FeedCreateModal/PickYourImage.vue'
import TooMuchImagesModal from '@/components/Modal/FeedCreateModal/TooMuchImagesModal.vue'
import PickYourTag from '@/components/Modal/FeedCreateModal/PickYourTag.vue'
// 기타
import ProfileImgChange from '@/components/Modal/ProfileImgChange.vue'
import CommentNeedContent from '@/components/Modal/CommentNeedContent.vue'
//팔로우, 팔로워
import MypageFollowingList from '@/components/Modal/FollowModal/Mypage/MypageFollowingList.vue'
import MypageFollowerList from '@/components/Modal/FollowModal/Mypage/MypageFollowerList.vue'
import UserpageFollowingList from '@/components/Modal/FollowModal/Userpage/UserpageFollowingList.vue'
import UserpageFollowerList from '@/components/Modal/FollowModal/Userpage/UserpageFollowerList.vue'
//좋아요
import LikesList from '@/components/Modal/LikesList.vue'
import AddPlayList from '@/components/Modal/AddPlayList.vue'
import AddToPlayList from '@/components/Modal/AddToPlayList.vue'
//정보변경
import nicknameErr from '@/components/Modal/UserInfoModal/nicknameErr.vue'
import pwchangeConfirm from '@/components/Modal/UserInfoModal/pwchangeConfirm.vue'
import pwchangeErr from '@/components/Modal/UserInfoModal/pwchangeErr.vue'
//이메일 찾기
import foundEmail from '@/components/Modal/EmailFindModal/foundEmail.vue'
import notfoundEmail from '@/components/Modal/EmailFindModal/notfoundEmail.vue'
import noTel from '@/components/Modal/EmailFindModal/noTel.vue'
//비밀번호 찾기
import noMatchEmail from '@/components/Modal/PwFindModal/noMatchEmail.vue'
import wrongEmail from '@/components/Modal/PwFindModal/wrongEmail.vue'


import { mapState } from 'vuex'

export default {
  components: {
    Loading,
    Create,
    Update,
    Navigation,
    //모달창
    LogoutModal,
    UserFeedSetting,
    CommentSetting,
    ProfileImgChange,
    LoginConfirm,
    SignupConfirm,
    EmotionTestTooMuchPick,
    FirstEmotionTestConfirm,
    EmotionTestError,
    EmotionTestPickMore,
    EmotionTestResult,
    ReturnToLogin,
    LoginFail,
    SignupFail,
    SignupFailPasswordError,
    CommentNeedContent,
    MoreInfoConfirm,
    MoreInfoError,
    PickYourImage,
    TooMuchImagesModal,
    PickYourTag,
    MypageFollowingList,
    MypageFollowerList,
    UserpageFollowingList,
    UserpageFollowerList,
    LikesList,
    AddPlayList,
    AddToPlayList,
    //정보변경
    nicknameErr,
    pwchangeConfirm,
    pwchangeErr,
     //이메일 찾기
    foundEmail,
    notfoundEmail,
    noTel,
    //비번 찾기
    noMatchEmail,
    wrongEmail,

  },
  computed:
    mapState([
      'navActive', 'showingNav', 'modalActive', 'profileImgChangeModalActive', 'commentSettingModalActive', 'logoutModalActive', 'userFeedSettingModalActive', 'userFeedSettingModalActive2', 'loginConfirmModalActive', 
      'signupConfirmModalActive', 'emotionTestTooMuchPickModalActive', 'firstEmotionTestConfirmModalActive', 'emotionTestErrorActive', 'emotionTestPickMoreModalActive', 'loading',
      'emotionTestResultModalActive', 'loginFailModalActive', 'signupFailModalActive1', 'signupFailModalActive2', 'ReturnToLoginModalActive', 'commentNeedContentModalActive',
      'moreInfoConfirmModalActive', 'feedUpdateActive', 'pickYourImageModalActive', 'tooMuchImagesModalActive', 'pickYourTagModalActive', 'mypagefollowingListActive', 'mypagefollowerListActive',
      'userpagefollowingListActive', 'userpagefollowerListActive', 'userFeedSettingModalActive2','likesListActive','addPlayListActive', 'nicknameErrModalActive', 'pwchangeConfirmModalActive', 'pwchangeErrModalActive',
      'foundEmailModalActive', 'notfoundEmailModalActive', 'noTelModalActive','addToPlayListActive', 'wrongEmailModalActive', 'noMatchEmailModalActive',
    ]),
}

</script>


<style scoped>
  #app {
    min-width: 100vw;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    flex-wrap: nowrap;
    background-color: rgba(235, 235, 235, 0.5);
    font-family: '비트로 프라이드 TTF', sans-serif !important;
    }
    @font-face {
      font-family:'비트로 프라이드 TTF';
      src: url('assets/font/비트로 프라이드 TTF.ttf') format('truetype');
  }
</style>