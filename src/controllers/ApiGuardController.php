<?php

namespace Chrisbjr\ApiGuard;

use Controller;
use Route;
use Request;
use Config;
use Log;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Input;
use EllipseSynergie\ApiResponse\Laravel\Response;
use League\Fractal\Manager;

class ApiGuardController extends Controller {

  /**
   * @var array
   */
  protected $apiMethods;

  /**
   * @var ApiKey|null|static
   */
  protected $apiKey = false;

  /**
   * @var string
   */
  protected $method;

  public function __construct()
  {
    $this->beforeFilter(function () {
      $manager = new Manager;
      $manager->parseIncludes(
        Input::get(
          Config::get('api-guard::includeKeyword', 'include'),
          array()
        )
      );
      $response = new Response($manager);

      $apiGuard = new ApiGuardService([
        'methods' => $this->getApiMethods(),
        'method' => $this->getMethod(),
        'apiKey' => $this->getKey(),
        'request' => Route::getCurrentRequest(),
        'response' => $response
      ]);

      $apiGuard->guard();

    });
  }

  public function getKey()
  {
    if ($this->key === false) {
      $this->key = $request->header(Config::get('api-guard::keyName'));

      // Try getting the key from elsewhere
      if (empty($key)) {
        $this->key = Input::get(Config::get('api-guard::keyName'));
      }
    }

    return $this->key;
  }

  // Let's get the method
  public function getMethod()
  {
    if (!$this->method) {
      Str::parseCallback(Route::currentRouteAction(), null);
      $routeArray = Str::parseCallback(Route::currentRouteAction(), null);

      $this->method = last($routeArray);
    }

    return $this->method;
  }

  // api-guard might not be the only before filter on the controller
  // loop through any before filters and pull out $apiMethods in the controller
  public function getApiMethods()
  {
    if (!$this->apiMethods)
      $beforeFilters = $this->getBeforeFilters();
      foreach ($beforeFilters as $filter) {
        if (!empty($filter['options']['apiMethods'])) {
          $this->apiMethods = $filter['options']['apiMethods'];
        }
      }
    }

    return $this->apiMethods;
  }

}
