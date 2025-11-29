package com.gestiondias.authservice.service;

import com.gestiondias.authservice.dto.LoginRequest;
import com.gestiondias.authservice.dto.RegisterRequest;
import com.gestiondias.authservice.model.Usuario;
import com.gestiondias.authservice.repository.UsuarioRepository;
import com.gestiondias.authservice.security.JwtUtil;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder encoder;

    // -------------------------------------------------------
    // 🔐 LOGIN (GENERA TOKEN)
    // -------------------------------------------------------
    public String login(LoginRequest req) {
        Usuario user = usuarioRepository.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!encoder.matches(req.getPassword(), user.getPassword())) {
            throw new RuntimeException("Contraseña incorrecta");
        }

        // email + rol
        return jwtUtil.generarToken(user.getEmail(), user.getRol());
    }

    // -------------------------------------------------------
    // 🔍 Obtener usuario por email (usado para mandar rol a Android)
    // -------------------------------------------------------
    public Usuario findByEmail(String email) {
        return usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));
    }

    // -------------------------------------------------------
    // 📝 REGISTRO
    // -------------------------------------------------------
    public Usuario register(RegisterRequest req) {
        Usuario u = Usuario.builder()
                .email(req.getEmail())
                .password(encoder.encode(req.getPassword()))
                .rol(req.getRol())
                .build();

        return usuarioRepository.save(u);
    }
}
