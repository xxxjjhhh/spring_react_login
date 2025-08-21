// AccessToken 만료시 Refreshing
export async function refreshAccessToken() {

    // 로컬 스토리지로 부터 RefreshToken 가져옴
    const refreshToken = localStorage.getItem("refreshToken");
    if (!refreshToken) throw new Error("RefreshToken이 없습니다.");

    const response = await fetch(`${import.meta.env.VITE_BACKEND_API_BASE_URL}/jwt/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
    });

    if (!response.ok) throw new Error("AccessToken 갱신 실패");

    // 성공 새 Token 저장
    const data = await response.json();
    localStorage.setItem("accessToken", data.accessToken);
    localStorage.setItem("refreshToken", data.refreshToken);

    return data.accessToken;
}


// AccessToken과 함께 fetch
export async function fetchWithAccess(url, options = {}) {

    // 로컬 스토리지로 부터 AccessToken 가져옴
    let accessToken = localStorage.getItem("accessToken");

    // 옵션에 Header 없는 경우 추가 + AccessToken 부착
    if (!options.headers) options.headers = {};
    options.headers["Authorization"] = `Bearer ${accessToken}`;

    // 요청 진행
    let response = await fetch(url, options);

    // AccessToken 만료로 401 뜨면, Refresh로 재발급
    if (response.status === 401) {

        try {

            // RefreshToken을 찾아서 리프래싱함
            accessToken = await refreshAccessToken();
            options.headers['Authorization'] = `Bearer ${accessToken}`;

            // 재요청
            response = await fetch(url, options);

        } catch (err) {

            localStorage.removeItem("accessToken");
            localStorage.removeItem("refreshToken");
            location.href = '/login';
        }

    }

    if (!response.ok) {
        throw new Error(`HTTP 오류 : ${response.status}`);
    }

    return response;
}