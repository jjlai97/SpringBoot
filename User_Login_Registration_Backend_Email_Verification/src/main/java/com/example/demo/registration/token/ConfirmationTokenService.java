package com.example.demo.registration.token;

import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@AllArgsConstructor
public class ConfirmationTokenService{

    private final ConfirmationTokenRepository confirmationTokenRepository;

    public void saveConfirmationToken(ConfirmationToken token) {
        confirmationTokenRepository.save(token);
    }


    public Optional<ConfirmationToken> getToken(String token) {
        return confirmationTokenRepository.findByToken(token);
    }

    public void setConfirmedAt(String token) {
      confirmationTokenRepository.findByToken(token).get().setConfirmedAt(LocalDateTime.now());
    }

    public Optional<ConfirmationToken> findByAppUserId(Long id) {
        return confirmationTokenRepository.findByAppUserId(id);
    }
}
