<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(RegisterRequest $request){
        $user = User::create([
            'name' => $request->name,
            'email'=> $request->email,
            'password'=> Hash::make($request->password),
            ]);

            return response()->json([
                'status' => 'Sucssuss',
                'message'=> 'User created successfully',
                'data' => [
                    'user' => UserResource::make( $user ),
                ]
            ], 201);
    }

    public function login(LoginRequest $request){

        /* There is a more compacet way to do the login function, which is:
        *   
        *   if(!Auth::attempt($request->only('email','password'))) { 
        *       Error json response in here 
        *   }
        */
        
        
        $user = user::where('email', $request->email)->first();

        if(! $user || ! Hash::check($request->password, $user->password)){
            return response()->json([
                'status'=> 'Error',
                'message'=> 'Incorrect'
            ],401);
        }
    
        $token = $user->createToken('auth-token') -> plainTextToken;

        return response()->json([
            'status'=> 'Success',
            'message'=> 'Logged In Successfully',
            'data'=> [
                'user' => UserResource::make( $user ),
                'token'=> $token
            ]
        ]);
    }

    public function profile(){
        return response()->json([
            'status'=> 'Success',
            'Data'=> [
                $user = UserResource::make( Auth::user() )
            ]
        ]);
    } 

    public function logout(Request $request){

        //Auth::user()->tokens()->delete();
        //It didn't work, due to a weird issue in tokens() function of hasApiToken() in my project, that I unfortunately couldn't figur it out.

        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'status'=> 'Success',
            'message' => 'User Logged out.'
            ]);
    }
}
