package com.pingwazi.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.Calendar;
import java.util.HashMap;

/**
 * @author pingwazi
 * @description jwt 的工具包
 */
public class JwtUtils {
    private static final String jwtClaimKey="tokenObj-key";
    private static final String jwtSecretKey="jwtSecret-Key";

    /**
     * 生成jwt的token串
     * @param value
     * @return
     */
    public static String createJwtToken(String value)
    {
        HashMap<String,Object> claims=new HashMap<>();
        claims.put(jwtClaimKey,value);
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.HOUR_OF_DAY,24);//当前时间添加24是小时,即token在24小时后过期
        return Jwts.builder()
                .setClaims(claims)//设置载荷部分
                .setExpiration(calendar.getTime())//设置过期时间
                .signWith(SignatureAlgorithm.HS512, jwtSecretKey)//设置加密算法
                .compact();
    }

    /**
     * 从jwttoken串中获取载荷值
     * @param tokenStr
     * @return
     */
    public static String getJwtTokenClaimValue(String tokenStr)
    {
        String result=null;
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecretKey)
                    .parseClaimsJws(tokenStr)
                    .getBody();

            if(claims.getExpiration().compareTo(Calendar.getInstance().getTime())>0)
            {
                //token未过期
                result=claims.get(jwtClaimKey,String.class);
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result;
    }
}
