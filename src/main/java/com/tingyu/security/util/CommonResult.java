package com.tingyu.security.util;

import cn.hutool.http.HttpStatus;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.Serializable;

@Data
@AllArgsConstructor
public class CommonResult implements Serializable {

    private Integer code;

    private String message;

    private Object data;

    private static final String MESSAGE_SUCCESS = "操作成功";

    private static final String MESSAGE_ERROR = "操作失败";

    public static CommonResult ok() {
        return CommonResult.ok(MESSAGE_SUCCESS);
    }

    public static CommonResult ok(String message) {
        return CommonResult.ok(message, null);
    }

    public static CommonResult ok(Object data) {
        return CommonResult.ok(MESSAGE_SUCCESS, data);
    }

    public static CommonResult ok(String message, Object data) {
        return new CommonResult(HttpStatus.HTTP_OK, message, data);
    }

    public static CommonResult error() {
        return CommonResult.error(MESSAGE_ERROR);
    }

    public static CommonResult error(String message) {
        return CommonResult.error(message, null);
    }

    public static CommonResult error(Object data) {
        return CommonResult.error(MESSAGE_ERROR, data);
    }

    public static CommonResult error(String message, Object data) {
        return new CommonResult(HttpStatus.HTTP_BAD_REQUEST, message, data);
    }

}
