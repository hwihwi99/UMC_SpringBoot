package com.umc.umc_springboot.src.user;

import com.umc.umc_springboot.config.BaseException;
import com.umc.umc_springboot.src.user.model.*;
import com.umc.umc_springboot.utils.AES128;
import com.umc.umc_springboot.utils.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

import static com.umc.umc_springboot.config.BaseResponseStatus.*;

/**
 * Service란?
 * Controller에 의해 호출되어 실제 비즈니스 로직과 트랜잭션을 처리: Create, Update, Delete 의 로직 처리
 * 요청한 작업을 처리하는 관정을 하나의 작업으로 묶음
 * dao를 호출하여 DB CRUD를 처리 후 Controller로 반환
 */
@Service    // [Business Layer에서 Service를 명시하기 위해서 사용] 비즈니스 로직이나 respository layer 호출하는 함수에 사용된다.
// [Business Layer]는 컨트롤러와 데이터 베이스를 연결
public class UserService {
    final Logger logger = LoggerFactory.getLogger(this.getClass()); // Log 처리부분: Log를 기록하기 위해 필요한 함수입니다.

    // *********************** 동작에 있어 필요한 요소들을 불러옵니다. *************************
    private final UserDao userDao;
    private final UserProvider userProvider;
    private final JwtService jwtService; // JWT부분은 7주차에 다루므로 모르셔도 됩니다!


    @Autowired //readme 참고
    public UserService(UserDao userDao, UserProvider userProvider, JwtService jwtService) {
        this.userDao = userDao;
        this.userProvider = userProvider;
        this.jwtService = jwtService; // JWT부분은 7주차에 다루므로 모르셔도 됩니다!

    }
    // ******************************************************************************
    // 회원가입(POST)
    public PostUserRes createUser(PostUserReq postUserReq) throws BaseException {
        // 중복 확인: 해당 닉네임을 가진 유저가 있는지 확인합니다. 중복될 경우, 에러 메시지를 보냅니다.
        if (userProvider.checkNickname(postUserReq.getNickname()) == 1) {
            throw new BaseException(POST_USERS_EXISTS_NICKNAME);
        }

        // 중복 확인 : 해당 이메일을 가진 유저가 있는지 확인합니다. => 만약 있으면 같은 사용자일 것 이므로 기존에 가입한 정보가 있다고 아이디/비밀번호 찾기로 넘어가라고 하기
        // 만약 탈퇴한 회원이라면 이건 못쓰는건데 이건 사용자 사정,,탈퇴를 하지 말았어야함
        if(userProvider.checkEmail(postUserReq.getEmail())==1){
            throw new BaseException(POST_USERS_EXISTS_EMAIL);
        }

        String pwd;
        String salt;

        try {
            // 암호화: postUserReq에서 제공받은 비밀번호를 보안을 위해 암호화시켜 DB에 저장합니다.
            // ex) password123 -> dfhsjfkjdsnj4@!$!@chdsnjfwkenjfnsjfnjsd.fdsfaifsadjfjaf
            salt = Math.round(new Date().getTime()*(Math.random()))+"123";
            postUserReq.setSalt(salt);
            pwd = new AES128(salt).encrypt(postUserReq.getPassword()); // 암호화코드
            postUserReq.setPassword(pwd);

        } catch (Exception ignored) { // 암호화가 실패하였을 경우 에러 발생
            throw new BaseException(PASSWORD_ENCRYPTION_ERROR);
        }
        try {
            int userIdx = userDao.createUser(postUserReq);
            return new PostUserRes(userIdx);

//  *********** 해당 부분은 7주차 수업 후 주석해제하서 대체해서 사용해주세요! ***********
//            //jwt 발급.
//            String jwt = jwtService.createJwt(userIdx);
//            return new PostUserRes(jwt,userIdx);
//  *********************************************************************
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    // 회원정보 수정(Patch)
    public void modifyUserAddress(PatchAddressReq patchAddressReq) throws BaseException {
        try {
            int result = userDao.modifyUserAddress(patchAddressReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(MODIFY_FAIL_ADDRESS);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    public void modifyUserPhoneNum(PatchPhoneNumReq patchPhoneNumReq) throws BaseException {
        try {
            int result = userDao.modifyUserPhoneNum(patchPhoneNumReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(MODIFY_FAIL_PHONENUM);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    public void modifyUserPassword(PatchPasswordReq patchPasswordReq) throws BaseException {
        if(userProvider.getUser(patchPasswordReq.getUserIdx())==null){
            throw new BaseException(USERS_EMPTY_USER_ID);
        }

        String pwd;
        String salt;

        // 새로 암호화해주기!
        try {
            // 암호화: postUserReq에서 제공받은 비밀번호를 보안을 위해 암호화시켜 DB에 저장합니다.
            // ex) password123 -> dfhsjfkjdsnj4@!$!@chdsnjfwkenjfnsjfnjsd.fdsfaifsadjfjaf
            salt = Math.round(new Date().getTime()*(Math.random()))+"123";
            patchPasswordReq.setSalt(salt);
            pwd = new AES128(salt).encrypt(patchPasswordReq.getPassword()); // 암호화코드
            patchPasswordReq.setPassword(pwd);

        } catch (Exception ignored) { // 암호화가 실패하였을 경우 에러 발생
            throw new BaseException(PASSWORD_ENCRYPTION_ERROR);
        }

        try {
            int result = userDao.modifyUserPassword(patchPasswordReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(MODIFY_FAIL_PAASSWORD);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    // 회원 상태 변경 : delete도 사용해보라고 하셨지만 user부분은 patch로 하고 아이템이나 그런 부분을 delete로 한번 시도해봐야겠습니다.

    // 1. 탈퇴
    public void deleteUser(PatchUserStatueReq patchUserStatueReq) throws BaseException{
        try {
            int result = userDao.deleteUser(patchUserStatueReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(FAILED_TO_DELETE);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    // 2. 비활성화
    public void deactiveUser (PatchUserStatueReq patchUserStatueReq) throws BaseException{
        GetUserRes user = userDao.getUser(patchUserStatueReq.getUserIdx());
        if(user.getStatus().equals("delete")){
            throw new BaseException(DELETE_ID);
        }
        else if(user.getStatus().equals("deactive")){
            throw new BaseException(DEACTIVE_ID);
        }
        try {
            int result = userDao.deactiveUser(patchUserStatueReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(FAILED_TO_DEACTIVE);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }

    // 3. 다시 활성화 (비활성화 -> 활성화 ONLY)
    public void reactiveUser(PatchUserStatueReq patchUserStatueReq) throws BaseException{
        GetUserRes user = userDao.getUser(patchUserStatueReq.getUserIdx());
        if(user.getStatus().equals("delete")){
            throw new BaseException(DELETE_ID);
        }
        else if(user.getStatus().equals("active")){
            throw new BaseException(ACTIVE_ID);
        }

        try {
            int result = userDao.reactiveUser(patchUserStatueReq); // 해당 과정이 무사히 수행되면 True(1), 그렇지 않으면 False(0)입니다.
            if (result == 0) { // result값이 0이면 과정이 실패한 것이므로 에러 메서지를 보냅니다.
                throw new BaseException(FAILED_TO_REACTIVE);
            }
        } catch (Exception exception) { // DB에 이상이 있는 경우 에러 메시지를 보냅니다.
            throw new BaseException(DATABASE_ERROR);
        }
    }
}
