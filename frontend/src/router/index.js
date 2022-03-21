import Vue from 'vue'
import VueRouter from 'vue-router'
import Login from '@/views/accounts/Login'
import MoreInfo from '@/views/accounts/MoreInfo'
import Signup from '@/views/accounts/Signup'
import KaKaoLogin from '@/views/accounts/KaKaoLogin'
import EmailFind from '@/views/accounts/EmailFind'
import PwFind from '@/views/accounts/PwFind'
import EmotionTest from '@/views/EmotionTest'

import Mypage from '@/views/user/Mypage.vue'
// import Userpage from '@/views/user/Userpage.vue'
import List from '@/components/user/List'
import PickDetail from '@/components/user/PickDetail'
// import UserList from '@/components/SearchUser/UserList'
// import UserPickItem from '@/components/SearchUser/UserPickItem'

import Main from '@/views/main/Main.vue'
import Setting from '@/views/Setting'
import UserInfo from '@/components/Settings/UserInfo'
import PwChange from '@/components/Settings/PwChange'
import Withdrawal from '@/components/Settings/Withdrawal'
import FeedDetail from '@/components/FeedDetail'
import SearchResult from '@/components/Search/SearchResult/SearchResult'
import SearchList from '@/components/Search/SearchResult/SearchList'

import store from '../store/index.js'

Vue.use(VueRouter)

const routes = [
  {
    path: '/login',
    name: 'Login',
    component: Login,
    meta: {
      loginRequired: false,
      testRequired: false,
      showingNav: false,
      title: '로그인'
    }
  },
  {
    path: '/moreInfo',
    name: 'MoreInfo',
    component: MoreInfo,
    meta: {
      loginRequired: true,
      testRequired: false,
      showingNav: false,
      title: '추가 정보 입력'
    }
  },
  {
    path: '/login/KaKaoLogin',
    name: 'KaKaoLogin',
    component: KaKaoLogin,
    meta: {
      loginRequired: false,
      testRequired: false,
      title: '카카오로 로그인하기'
    }
  },
  {
    path: '/signup',
    name: 'Signup',
    component: Signup,
    meta: {
      loginRequired: false,
      testRequired: false,
      showingNav: false,
      title: '시민권 발급받기'
    }
  },
  {
    path: '/password-find',
    name: 'Password-find',
    component: PwFind,
    meta: {
      loginRequired: false,
      testRequired: false,
      showingNav: false,
      title: '비밀번호 찾기'
    },
  },
  {
    path: '/email-find',
    name: 'EmailFind',
    component: EmailFind,
    meta: {
      loginRequired: false,
      testRequired: false,
      showingNav: false,
      title: '이메일 찾기'
    },
  },
  {
    path: '/mypage',
    name: 'Mypage',
    redirect: '/mypage/feed',
    component: Mypage,
    meta: {
      loginRequired: true,
      testRequired: true, 
      showingNav: true,
      title: '마이 페이지'
    },
    children: [
      {
        path: ':tab',
        component: List,
        props: true,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
        },
      },
      {
        path: 'item/:pickNo',
        component: PickDetail,
        props: true,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
        },
      }
    ]
  },
  {
    path: '/user/:userId',
    name: 'Userpage',
    redirect: '/user/:userId/feed',
    component: Mypage,
    props: true,
    meta: {
      loginRequired: true,
      testRequired:  true,
      showingNav: true,
    },
    children: [
      {
        path: ':tab',
        component: List,
        props: true,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
        },
      },
      {
        path: 'item/:pickNo',
        component: PickDetail,
        props: true,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
        },
      }
    ]
  },
  {
    path:'/main',
    name:'Main',
    component:Main,
    meta: {
      loginRequired: true,
      testRequired: true,
      showingNav: true,
    },
  },
  {
    path: '/emotiontest',
    name: 'EmotionTest',
    component: EmotionTest,
    meta: {
      loginRequired: true,
      testRequired: false,
      showingNav: false,
      title: '감정 테스트'
    },
  },
  {
    path: '/setting',
    name: 'Setting',
    redirect: '/setting/info',
    component: Setting,
    meta: {
      loginRequired: true,
      testRequired: true,
      showingNav: true,
      title: '설정 페이지'
    },
    children: [
      {
        path: 'info',
        component: UserInfo,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
          title: '프로필 수정'
        },
      },
      {
        path: 'password',
        component: PwChange,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
          title: '비밀번호 수정'
        },
      },
      {
        path: 'withdrawal',
        component: Withdrawal,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
          title: '회원 탈퇴'
        },
      },
    ],  
  },
  {
    path: '/feed/:feedNo',
    name: 'FeedDetail',
    component: FeedDetail,
    props:true,
    meta: {
      loginRequired: true,
      testRequired: true,
      showingNav: true,
      title: '피드 상세정보'
    },
  },
  {
    path: '/search',
    name: 'SearchResult',
    redirect: '/search/feed',
    component: SearchResult,
    props: true,
    meta: {
      loginRequired: true,
      testRequired: true, 
      showingNav: true,
    },
    children: [
      {
        path: ':tab',
        component: SearchList,
        props: true,
        meta: {
          loginRequired: true,
          testRequired: true,
          showingNav: true,
        },
      },
    ]
  },
]

const router = new VueRouter({
  mode: 'history',
  base: process.env.BASE_URL,
  routes
})

let token = window.sessionStorage.getItem('at-jwt-access-token');
const jwt = require('jsonwebtoken');
const decodeAccessToken = jwt.decode(token)

//유저 정보 업데이트
const userUpdate = new Promise(() => {
  console.log('user data updated!')
  if(decodeAccessToken != null){
  store.commit('userUpdate', decodeAccessToken)
  }
})

router.beforeEach((to, from, next) => {
  console.log('여기에서',from)
  console.log('여기로 갈거야',to)
  // 라우터 이동 시 토큰이 필요함
  token = window.sessionStorage.getItem('at-jwt-access-token');
  console.log(token)
  store.commit('load', true)
  //지정되지 않은 라우트로 이동할 경우 메인으로 redirect
  if (!to.matched.length){
    console.log('do not matched!!', to)
    next({ name:'Main' })
  }
  //네비게이션 랜더 유무
  store.commit('navActivate2', to.meta.showingNav)
  
  // 네비게이션 바 Active와 매칭
  if (to.name == 'Main'){store.commit('navActivate', 1)}
  else if (to.matched.length && to.matched[0].path == '/mypage'){store.commit('navActivate', 2)}
  else if (to.matched.length && to.matched[0].path == '/setting'){store.commit('navActivate', 4)}
  else {store.commit('navActivate', -1)}

  //로그인이 필요한 서비스의 경우 로그인 페이지로 redirect
  if (to.meta.loginRequired && !token){
    console.log('로그인')
    next({ name:'Login' })
  }
  //페이지 새로고침 등 발생했을 때 유저정보 store 갱신
  if (to.meta.loginRequired && token && !store.state.userInfo){
    userUpdate.then(() => next())
  }
  // 감정 테스트가 필요한 경우 테스트페이지로 redirect
  if (to.meta.testRequired && store.state.userInfo != null && !store.state.userInfo.mood){
    console.log(store.state.userInfo.mood)
    next({ name:'EmotionTest' })
  }
  //로그인 된 사용자가 로그인 or 회원가입 페이지로 가려고 할 경우
  if (!to.meta.loginRequired && store.state.userInfo && token){
    console.log('메인')
    next({ name:'Main' })
  }
  const user = JSON.parse(window.sessionStorage.getItem('userInfo'))
  
  if (to.params.userId && to.params.userId ==  user.no && to.path.includes('item')){
    next({ path: `/mypage/item/${to.params.pickNo}` })
  }

  else if (to.params.userId && to.params.userId ==  user.no && to.path.includes('user')){
    next({ path: `/mypage` })
  }

  next()
})

const DEFAULT_TITLE = 'Emotion Planet'

router.afterEach((to) => {
  // Use next tick to handle router history correctly
  // see: https://github.com/vuejs/vue-router/issues/914#issuecomment-384477609
  Vue.nextTick(() => {
      document.title = to.meta.title || DEFAULT_TITLE;
  });
});

// router.push의 중복 에러 해결방법
const originalPush = VueRouter.prototype.push;
VueRouter.prototype.push = function push(location) {
	return originalPush.call(this, location).catch(err => {
		if (err.name !== 'NavigationDuplicated') throw err;
	});
};

export default router
