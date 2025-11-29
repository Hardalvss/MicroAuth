package com.gestiondias.authservice.controller;

import java.util.Map;

import com.gestiondias.authservice.dto.LoginRequest;
import com.gestiondias.authservice.dto.RegisterRequest;
import com.gestiondias.authservice.model.Usuario;
import com.gestiondias.authservice.service.AuthService;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    // -------------------------------------------------------
    // 🔵 REGISTRO
    // -------------------------------------------------------
    @PostMapping("/register")
    public Usuario register(@RequestBody RegisterRequest req) {
        return authService.register(req);
    }

    // -------------------------------------------------------
    // 🔐 LOGIN (RETORNA TOKEN + ROL)
    // -------------------------------------------------------
    @PostMapping("/login")
    public Map<String, String> login(@RequestBody LoginRequest req) {

        // 1️⃣ Generar token
        String token = authService.login(req);

        // 2️⃣ Obtener usuario para extraer el rol
        Usuario user = authService.findByEmail(req.getEmail());

        // 3️⃣ Respuesta final para Android
        return Map.of(
                "token", token,
                "rol", user.getRol()  // 🔥 importante para navegación
        );
    }
}
