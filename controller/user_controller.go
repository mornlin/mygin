package controller

import (
	"log"
	"mygin/common"
	"mygin/dto"
	"mygin/model"
	"mygin/response"
	"mygin/util"
	"net/http"

	"golang.org/x/crypto/bcrypt"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jinzhu/gorm"
)

func Register(ctx *gin.Context) {
	db := common.DB
	var requestUser = model.User{}
	ctx.Bind(&requestUser)
	log.Println("Name:" + requestUser.Name)
	log.Println("Telephone:" + requestUser.Telephone)
	log.Println("Password:" + requestUser.Password)

	if len(requestUser.Telephone) != 11 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "手机号码必须11位")
		return
	}

	if len(requestUser.Password) < 6 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "密码不能少于6位")
		return
	}

	if len(requestUser.Name) == 0 {
		requestUser.Name = util.RandomString(10)
	}

	if isTelephoneExist(db, requestUser.Telephone) {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "用户已存在")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(requestUser.Password), bcrypt.DefaultCost)
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, nil, "加密错误")
		return
	}

	newUser := model.User{
		Name:      requestUser.Name,
		Telephone: requestUser.Telephone,
		Password:  string(hashedPassword),
	}
	db.Create(&newUser)

	token, err := common.ReleaseToken(newUser)
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, nil, "系统异常")
		return
	}

	response.Success(ctx, gin.H{"token": token}, "注册成功")
}

func Login(ctx *gin.Context) {
	var requestUser = model.User{}
	ctx.Bind(&requestUser)
	log.Println("Telephone:" + requestUser.Telephone)
	log.Println("Password:" + requestUser.Password)

	if len(requestUser.Telephone) != 11 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "手机号码必须11位")
		return
	}

	if len(requestUser.Password) < 6 {
		response.Response(ctx, http.StatusUnprocessableEntity, 422, nil, "密码不能少于6位")
		return
	}

	db := common.GetDB()
	var user model.User
	db.Where("telephone = ?", requestUser.Telephone).First(&user)
	if user.ID == 0 {
		response.Response(ctx, http.StatusUnprocessableEntity, 400, nil, "用户不存在")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestUser.Password)); err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 400, nil, "密码错误")
		return
	}

	token, err := common.ReleaseToken(user)
	if err != nil {
		response.Response(ctx, http.StatusUnprocessableEntity, 500, nil, "系统异常")
		return
	}

	// ctx.JSON(200, gin.H{
	// 	"code": 200,
	// 	"data": gin.H{"token": token},
	// 	"msg":  "登录成功",
	// })

	response.Success(ctx, gin.H{"token": token}, "登录成功")
}

func Info(ctx *gin.Context) {
	user, _ := ctx.Get("user")
	ctx.JSON(http.StatusOK, gin.H{"code": 200, "data": gin.H{"user": dto.ToUserDto(user.(model.User))}})
}

func isTelephoneExist(db *gorm.DB, telephone string) bool {
	var user model.User
	db.Where("telephone = ?", telephone).First(&user)
	if user.ID != 0 {
		return true
	}
	return false
}
