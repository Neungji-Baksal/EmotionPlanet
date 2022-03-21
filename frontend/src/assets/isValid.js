// class validateData{
    // constructor(data){
    //     this.data = data
    // }

    // validateEmail(){
    //     // ^ 시작일치, $ 끝 일치
    //     // {2, 3} 2개 ~ 3개
    //     // * 0회 이상, + 1회$ 이상
    //     // [-.] - 또는  또는 .
    //     // ? 없거나 1회
    //     let regexp =
    //     /^[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$/i;
    //     return regexp.test(this.userEmail) ? true : false;
    // }
// } 
export default {
    constructor(data){
        this.data = data
    },

    validateEmail3(){
        // ^ 시작일치, $ 끝 일치
        // {2, 3} 2개 ~ 3개
        // * 0회 이상, + 1회$ 이상
        // [-.] - 또는  또는 .
        // ? 없거나 1회
        let regexp =
        /^[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*@[0-9a-zA-Z]([-.]?[0-9a-zA-Z])*.[a-zA-Z]{2,3}$/i;
        return regexp.test(this.userEmail) ? true : false;
    }

}

