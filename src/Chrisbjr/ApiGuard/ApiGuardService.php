<?php namespace Chrisbjr\ApiGuard;

use EllipseSynergie\ApiResponse\Laravel\Response;
use Request;

class ApiGuardService {

  /**
   * @var array
   */
  protected $apiMethods;

  public function setApiMethods($methods = [])
  {
    $this->apiMethods = $methods;
  }


  /**
   * @var ApiKey|null|static
   */
  protected $apiKey = null;

  public function setApiKey($key)
  {
    if (!$key) return;

    $apiKey = ApiKey::where('key', '=', $key)->first();

    if ($apiKey->id) {
      $this->apiKey = $apiKey;
    }
  }


  /**
   * @var \EllipseSynergie\ApiResponse\Laravel\Response
   */
  protected $response;

  public function setResponse(Response $response)
  {
    $this->response = $response;
  }


  /**
   * @var Request
   */
  protected $request;

  public function setRequest(Request $request)
  {
    $this->request = $request;
  }


  /**
   * @var string
   */
  protected $method;

  public function setMethod($method)
  {
    $this->method = $method;
  }

  public function __construct(Array $options = [])
  {
    foreach ($options as $option => $value) {
      $method = 'set' . ucfirst($option);
      if (method_exists($this, $method)) {
        $this->$method($value);
      }
    }
  }

  public function guard()
  {
    if (!$this->method) {
      $this->response->errorMethodNotAllowed();
      return;
    }

    $keyAuthentication = $this->authenticable();
    if ($keyAuthentication) {
      $this->authenticate();
      $this->authorize();
    }

    $this->checkLimit($method, $apiMethods, $request);

    $this->logRequest($keyAuthentication, $request);
  }

  // We should check if key authentication is enabled for this method
  public function authenticable()
  {
    if (
      isset($this->apiMethods[$this->method]['keyAuthentication'])
      && $this->apiMethods[$this->method]['keyAuthentication'] === false
    ) {
        return false;
    }

    return true;
  }

  public function authenticate()
  {
    if (!$this->apiKey || !$this->apiKey->id) {
      $this->response->errorUnauthorized();
    }
  }

  // Check level of API
  public function authorize()
  {
    if (!empty($this->apiMethods[$this->method]['level'])) {
      if ($this->apiKey->level < $this->apiMethods[$this->method]['level']) {
        $this->response->errorForbidden();
      }
    }
  }

  public function checkLimit()
  {
    if ($this->apiKey && $this->apiKey->ignore_limits) {
      Log::warning('ignoring limits');
      return;
    }

    // Then check the limits of this method
    if (empty($this->apiMethods[$this->method]['limits'])) {
      return;
    }

    // @todo verify if statement
    if (Config::get('api-guard::logging') === false) {
      Log::warning("[Chrisbjr/ApiGuard] You specified a limit in the $method method but API logging needs to be enabled in the configuration for this to work.");
    }

    $this->checkKeyLimit();
    $this->checkMethodLimit();
  }

  // We get key level limits first
  public function checkKeyLimit()
  {
    $limits = $this->apiMethods[$this->method]['limits'];

    if (empty($limits['key'])) {
      return;
    }

    Log::info("key limits found");

    $keyLimit = $limits['key']['limit'] ? (int) $limits['key']['limit'] : 0;
    if (!$keyLimit) {
      Log::warning("[Chrisbjr/ApiGuard] You defined a key limit to the " . Route::currentRouteAction() . " route but you did not set a valid number for the limit variable.");
      return;
    }

    // This means the apikey is not ignoring the limits
    $keyIncrement = $limits['key']['increment']
      ? $limits['key']['increment']
      : Config::get('api-guard::keyLimitIncrement')
    ;
    $keyIncrementTime = strtotime('-' . $keyIncrement);

    if (!$keyIncrementTime) {
      Log::warning("[Chrisbjr/ApiGuard] You have specified an invalid key increment time. This value can be any value accepted by PHP's strtotime() method");
      return;
    }

    // Count the number of requests for this method using this api key
    $apiLogCount = ApiLog::where('api_key_id', '=', $this->apiKey->id)
      ->where('route', '=', Route::currentRouteAction())
      ->where('method', '=', $request->getMethod())
      ->where('created_at', '>=', date('Y-m-d H:i:s', $keyIncrementTime))
      ->where('created_at', '<=', date('Y-m-d H:i:s'))
      ->count();

    if ($apiLogCount >= $keyLimit) {
      Log::warning("[Chrisbjr/ApiGuard] The API key ID#{$this->apiKey->id} has reached the limit of {$keyLimit} in the following route: " . Route::currentRouteAction());
      $this->response->errorUnwillingToProcess('You have reached the limit for using this API.');
      return;
    }
  }

  // Then the overall method limits
  public function checkMethodLimit()
  {
    $limits = $this->apiMethods[$this->method]['limits'];

    if (empty($limits['method'])) {
      return;
    }

    $methodLimit = 0;
    if ($limits['method']['limit']) {
      $methodLimit = (int) $limits['method']['limit'];
    }

    if (!$methodLimit) {
      Log::warning("[Chrisbjr/ApiGuard] You defined a method limit to the " . Route::currentRouteAction() . " route but you did not set a valid number for the limit variable.");
      return;
    }

    $methodIncrement = !empty($limits['method']['increment'])
      ? $limits['method']['increment']
      : Config::get('api-guard::keyLimitIncrement')
    ;

    $methodIncrementTime = strtotime('-' . $methodIncrement);
    if ($methodIncrementTime == false) {
      Log::warning("[Chrisbjr/ApiGuard] You have specified an invalid method increment time. This value can be any value accepted by PHP's strtotime() method");
      return;
    }

    // Count the number of requests for this method
    $apiLogCount = ApiLog::where('route', '=', Route::currentRouteAction())
      ->where('method', '=', $request->getMethod())
      ->where('api_key_id', '=', $this->apiKey->id) // @done: --added
      ->where('created_at', '>=', date('Y-m-d H:i:s', $methodIncrementTime))
      ->where('created_at', '<=', date('Y-m-d H:i:s'))
      ->count()
    ;

    if ($apiLogCount >= $methodLimit) {
      Log::warning("[Chrisbjr/ApiGuard] The API has reached the method limit of {$methodLimit} in the following route: " . Route::currentRouteAction());
      $this->response->errorUnwillingToProcess('The limit for using this API method has been reached');
      return;
    }
  }

  // Log this API request
  public function logRequest()
  {
    if (Config::get('api-guard::logging') && $this->authenticable()) {
      $apiLog = new ApiLog;
      $apiLog->api_key_id = $this->apiKey->id;
      $apiLog->route = Route::currentRouteAction();
      $apiLog->method = $this->request->getMethod();
      $apiLog->params = http_build_query(Input::all());
      $apiLog->ip_address = $this->request->getClientIp();
      $apiLog->save();
    }
  }
}
