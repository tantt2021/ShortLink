package com.tantt.shortlink.model.vo;

import cn.dev33.satoken.stp.SaTokenInfo;
import lombok.Data;

import java.io.Serializable;

/**
 * @Author: tantingjia
 * @Date: 2024/9/8 17:09
 **/
@Data
public class TokenLoginUserVO extends LoginUserVO implements Serializable {
    public static final long serialVersionUID = 2405172041950251807L;

    /**
     * token信息
     */
    private transient SaTokenInfo saTokenInfo;
}
