<?php


namespace thans\jwt\middleware;

use thans\jwt\exception\TokenExpiredException;
use thans\jwt\exception\TokenBlacklistGracePeriodException;

class JWTAuthAndRefresh extends BaseMiddleware
{
    public function handle($request, \Closure $next)
    {
        // OPTIONS请求直接返回
        if ($request->isOptions()) {
            return response();
        }

        // 验证token
        try {
            p('JWTAuthAndRefresh.........before..........');
            $this->auth->auth();
            p('JWTAuthAndRefresh.........after..........');
        } catch (TokenExpiredException $e) { // 捕获token过期
            p('TokenExpiredException.........');
            // 尝试刷新token
            try {
                p('TokenExpiredException.........try--------');
                $this->auth->setRefresh();
                $token = $this->auth->refresh();
                p('TokenExpiredException.........try--------'. $token);
                // $payload = $this->auth->auth(false);
                // $request->uid = $payload['uid']->getValue();

                $response = $next($request);
                return $this->setAuthentication($response, $token);
            } catch (TokenBlacklistGracePeriodException $e) { // 捕获黑名单宽限期
                p('TokenBlacklistGracePeriodException.........catch--------');
                // $payload = $this->auth->auth(false);
                // $request->uid = $payload['uid']->getValue();

                return $next($request);
            }
        } catch (TokenBlacklistGracePeriodException $e) { // 捕获黑名单宽限期
            p('TokenBlacklistGracePeriodException.........11111111111--------');
            // $payload = $this->auth->auth(false);
            // $request->uid = $payload['uid']->getValue();
        }

        return $next($request);
    }
}
