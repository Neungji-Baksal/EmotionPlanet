<template>
  <section id="act_container">
    <article id="category_container">
      <span v-for="(category, idx) in act_categories" :key="category" 
      class="categories" @click="checkCategory(category)" 
      :class="[selectedCategory == category ? 'checked':'',
      {'top':idx==0}, {'bottom':idx==5}]">
        {{ category }}
      </span>
    </article>
    <article id="tag_container" v-for="category in act_categories" :key="category" v-show="selectedCategory == category">
      <act-tag v-for="(tag, idx) in act_details[category]" :key="category+'-'+idx" :tag="tag" @checked="checkTag" @selected="select"  />
    </article>
  </section>
</template>

<script>
import ActTag from '@/components/FeedCreate/ActTag'
// 카테고리는 달라도 태그 단어가 같으면 누르는게 유지되는 버그가 있음. 카테고리에 다 다른 태그를 넣는 방법도 있지만 코드를 고치는 방법도 있음
export default {
  data: function(){
    return {
      selectedCategory: '운동',
      act_categories: ['운동', '취미', '휴식/여가', '일상', '감정표현'],
      act_details: {
        '운동': ['했어요', '갔어요','뛰었어요', '움직였어요','탔어요', '찼어요', '쳤어요', '걸었어요', '들었어요', '올라갔다'], 
        '취미': ['봤어요', '했어요', '들었어요', '갔어요', '만들었어요', '읽었어요', '배웠어요', '춤췄어요', '노래 불렀어요', '그렸어요', '썼어요'],
        '휴식/여가': ['갔어요', '먹었어요', '마셨어요', '놀았어요', '봤어요', '했어요', '잤어요', '쉬었어요', '누웠어요', '앉았어요', '멍때렸어요', '얘기했어요'],
        '일상': ['일했어요', '먹었어요', '잤어요', '공부했어요', '만났어요', '갔어요', '씻었어요', '샀어요', '치웠어요', '버렸어요',  '놀았어요' ],
        '감정표현': ['울었어요', '싸웠어요', '소리 질렀어요', '웃었어요', '던졌어요', '부쉈어요', '찢었어요'], 
      },
      selectedTag: null,
      acttag: {},
    }
  },
  components: {
    ActTag
  },
  methods: {
    checkCategory: function(category){
      this.selectedCategory = category
    },
    checkTag(payload){
      if (this.selectedTag){
        console.log(payload)
        this.$children.forEach(ele => {
          if (ele.isChecked && ele._props.tag != payload){
            ele.isChecked = false
          }
        })
      }
      this.selectedTag = payload
      this.acttag = {name: `${this.selectedTag}`, type: 0}
      this.$store.commit('feedTag', this.acttag)
      this.$emit('check-category',this.selectedTag)
    },
    select(payload) {
      console.log(payload)
      this.$emit('selected', payload)
    }
  },
  computed: {

  },
}
</script>

<style scoped>
  #act_container {
    display: flex;
    border: 2px #cccccc solid;
    border-radius: 10px;
    width: 80%;
    height: 14.5rem;
    margin: 0;
  }

  #category_container {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    border-right: 1px #cccccc solid;
    width: 25%;
    overflow-y: scroll;
  }

  #tag_container {
    padding: 0.5rem;
    width: 80%;
    overflow-y: scroll;
    text-align: center;
  }

  .categories {
    font-size: 1.25rem;
    font-weight: bold;
    width: 100%;
    margin: 0;
    padding: 0.25rem;
    text-align: center;
    cursor: pointer;
  }

  .checked {
    color: white;
    font-weight: bold;
    background-color: #5E39B3;
  }

  .top {
    border-top-left-radius: 0.5rem;
  }

  .bottom {
    border-bottom-left-radius: 0.5rem;
  }
</style>