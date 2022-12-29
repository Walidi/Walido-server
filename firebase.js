import { initializeApp } from "firebase/app";
import { getStorage } from "firebase/storage";

const firebaseConfig = {
  apiKey: "AIzaSyAw80HvGbV0yrmrHJYWiivc3f1912YcIF4",
  authDomain: "webauth-2ac45.firebaseapp.com",
  projectId: "webauth-2ac45",
  storageBucket: "webauth-2ac45.appspot.com",
  messagingSenderId: "136626980163",
  appId: "1:136626980163:web:963db3dbdaf09d9bab5bf6",
  measurementId: "G-W2THV32VWK"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
export const storage = getStorage(app);