<?php

namespace App\Http\Controllers;

use App\Models\role;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Validator;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Tymon\JWTAuth\Facades\JWTAuth;


class AuthController extends Controller
{


    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }

    /**
  * Refresh a token.
  *
  * @return \Illuminate\Http\JsonResponse
  */
 public function refresh()
 {
     $token = JWTAuth::parseToken()->refresh();
     return $this->respondWithToken($token);
 }


     /**
  * Get the token array structure.
  *
  * @param  string $token
  *
  * @return \Illuminate\Http\JsonResponse
  */
 protected function respondWithToken($token)
 {
     $expiration = JWTAuth::factory()->getTTL() * 60;

     return response()->json([
         'access_token' => $token,
         'token_type' => 'bearer',
         'expires_in' => $expiration,
         'expiration_date' => now()->addSeconds($expiration)->toDateTimeString(),
     ]);
 }

 public function me()
 {
     return response()->json(auth()->user());
 }


 public function register(Request $request){
     try{
         $validator = Validator::make($request->all(),[
             'username' => 'required|string|max:50',
             'name' => 'required|string|max:50',
             'email' => 'required|string|email|max:50|unique:users',
             'password'=> 'required|string|min:6',
             'role_id' => 'required|integer',
         ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(),400);
        }
        $user = User::create([
            'username' => $request->get('username'),
            'name' => $request->get('name'),
            'email'=> $request->get('email'),
            'password'=> bcrypt($request->get('password')),
            'role_id' => $request->get('role_id'),
        ]);

        $token = JWTAuth::fromUser($user);
        return response()->json(compact('user','token'),201);
    }
    catch(\Exception $e){
        return response()->json([
            'message' => 'Error al crear el usuario',
            'error'=>$e->getMessage()],500);
    }
 }


 public function login(Request $request)
 {
     try {
         if (!Auth::attempt($request->only('email', 'password'))) {
             return response()->json(['message' => 'Unauthorized'], 401);
         }

         $user = User::where('email', $request['email'])
             ->addSelect([
                 'rol' => role::select('role')->whereColumn('role_id', 'id')
             ])
             ->firstOrFail();

         $token = JWTAuth::fromUser($user);
         Log::info('Token generado: ' . $token);

         return response()->json([
             'message' => 'Success',
             'user' => $user,
             'token' => $this->respondWithToken($token),
         ]);
     } catch (\Exception $e) {
         return response()->json([
             'message' => 'Error al iniciar sesión',
             'error' => $e->getMessage()
         ], 500);
     }
 }


 public function userDetails()
 {
     $user = Auth::guard('api')->user();
     return response()->json( $user);
 }

 public function logout(){
     /**
    * @var user $user
   */
   $user = Auth::user();
   //Aun no hay JWT
   $userToken = $user->tokens();
   $userToken->delete();
   return response(['message'=> 'Logged Out!!'],200);
}

}

