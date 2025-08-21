import { useEffect, useState } from "react";
import { fetchWithAccess } from "../util/fetchUtil";

// .env로 부터 백엔드 URL 받아오기
const BACKEND_API_BASE_URL = import.meta.env.VITE_BACKEND_API_BASE_URL;

function UserPage() {

    // 정보
    const [userInfo, setUserInfo] = useState(null);
    const [error, setError] = useState('');

    // 페이지 방문시 유저 정보 요청
    useEffect(() => {

        const userInfo = async () => {

            try {

                const res = await fetchWithAccess(`${BACKEND_API_BASE_URL}/user`, {
                    method: 'GET',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                });

                if (!res.ok) throw new Error("유저 정보 불러오기 실패");

                const data = await res.json();
                setUserInfo(data);

            } catch (err) {
                setError("유저 정보를 불러오지 못했습니다.");
            }

        };

        userInfo();

    }, []);

    return (
        <div>
            <h1>내 정보</h1>
            <p>아이디: {userInfo?.username}</p>
            <p>닉네임: {userInfo?.nickname}</p>
            <p>이메일: {userInfo?.email}</p>
        </div>
    );
}

export default UserPage;