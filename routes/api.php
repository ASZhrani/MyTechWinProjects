<?php

use App\Http\Requests\RegisterRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\Auth\AuthController;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');


Route::post('register',  [AuthController::class, 'register']);

Route::get('login',  [AuthController::class, 'login']);


Route::middleware('auth:sanctum') -> group(function () {

        Route::get('profile', [AuthController::class,'profile']);
        Route::post('logout', [AuthController::class,'logout']);
});

    


