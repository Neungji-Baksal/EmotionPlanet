package com.ssafy.project.EmotionPlanet.Util;

import com.wrapper.spotify.SpotifyApi;
import com.wrapper.spotify.exceptions.SpotifyWebApiException;
import com.wrapper.spotify.model_objects.credentials.ClientCredentials;
import com.wrapper.spotify.requests.authorization.client_credentials.ClientCredentialsRequest;
import org.apache.hc.core5.http.ParseException;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class createAccesstoken {
	
	private String clientId = "1f072a1166fd47dfbe23973e82a573ee";
	private String clientSecret = "a8709cb4a4a249e5b586ac8316cb1bb6";
	
	private SpotifyApi spotifyApi = new SpotifyApi.Builder().setClientId(clientId).setClientSecret(clientSecret)
			.build();

	public  String accesstoken() {
		ClientCredentialsRequest clientCredentialsRequest = spotifyApi.clientCredentials().build();
		try {
			final ClientCredentials clientCredentials = clientCredentialsRequest.execute();
			// Set access token for further "spotifyApi" object usage
			spotifyApi.setAccessToken(clientCredentials.getAccessToken());
			return spotifyApi.getAccessToken();
		} catch (IOException | SpotifyWebApiException | ParseException e) {
			System.out.println("Error: " + e.getMessage());
			return null;
		}
	}
}