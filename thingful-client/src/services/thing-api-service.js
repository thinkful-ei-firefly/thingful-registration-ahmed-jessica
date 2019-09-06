import config from '../config'
import TokenService from './token-service';

const ThingApiService = {
  getThings() {
    return fetch(`${config.API_ENDPOINT}/things`, {
      headers: {
        "Authorization": `Bearer ${TokenService.getAuthToken()}`,
      },
    })
      .then(res =>
        (!res.ok)
          ? res.json().then(e => Promise.reject(e))
          : res.json()
      )
  },
  getThing(thingId) {
    return fetch(`${config.API_ENDPOINT}/things/${thingId}`, {
      headers: {
        "Authorization": `Bearer ${TokenService.getAuthToken()}`,
      },
    })
      .then(res =>
        (!res.ok)
          ? res.json().then(e => Promise.reject(e))
          : res.json()
      )
  },
  getThingReviews(thingId) {
    return fetch(`${config.API_ENDPOINT}/things/${thingId}/reviews`, {
      headers: {
        "Authorization": `Bearer ${TokenService.getAuthToken()}`,
      },
    })
      .then(res =>
        (!res.ok)
          ? res.json().then(e => Promise.reject(e))
          : res.json()
      )
  },
  postReview(thingId, text, rating) {
    return fetch(`${config.API_ENDPOINT}/reviews`, {
      method: 'POST',
      headers: {
        "Authorization": `Bearer ${TokenService.getAuthToken()}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        thing_id: thingId,
        rating,
        text,
      }),
    })
      .then(res =>
        (!res.ok)
          ? res.json().then(e => Promise.reject(e))
          : res.json()
      )
  }
}

export default ThingApiService
