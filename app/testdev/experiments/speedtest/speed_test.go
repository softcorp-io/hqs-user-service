package testing

import (
	"fmt"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	client "github.com/softcorp-io/hqs-user-service/testdev/client"
	mock "github.com/softcorp-io/hqs-user-service/testdev/mock"
	proto "github.com/softcorp-io/hqs_proto/go_hqs/hqs_user_service"
)

const amount = 500

func resultToFile(foldername string, result string) {
	f, err := os.Create("./results/" + foldername + "/results.yaml")
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	_, err = f.WriteString(result)
	if err != nil {
		log.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	var wgServer sync.WaitGroup
	log.Println("Speed.Test.Main", "Setting up server...")
	wgServer.Add(1)
	go mock.RunServer(&wgServer)
	wgServer.Wait()

	log.Println("Speed.Test.Main", "Server has been set up.")

	code := m.Run()

	mock.TearDownMongoDocker()
	mock.TearDownRedisDocker()

	os.Exit(code)
}

func TestAuthSpeed(t *testing.T) {
	t.Parallel()
	testname := "authSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err := client.Auth(cl, seedEmail, seedPassword, wg)
			if err != nil {
				log.Println("Warning:", "Test.Speed.Speed", "Could not authenticate")
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.Speed.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestCreateSpeed(t *testing.T) {
	t.Parallel()
	testname := "createSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.Create.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for i, cl := range clients {
		createName := fmt.Sprintf("Crete User %d", i)
		createEmail := fmt.Sprintf("createuser%d@softcorp.io", i)
		createPassword := fmt.Sprintf("RandomPassword1234%d", i)
		createPhone := ""
		createAllowView := false
		createAllowCrete := false
		createAllowDelete := false
		createAllowPermission := false
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.Create(cl, createName, createEmail, createPhone, createPassword, createAllowView, createAllowCrete, createAllowDelete, createAllowPermission, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.Create.Speed", fmt.Sprintf("Could not create user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.Create.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGenerateSignupTokenSpeed(t *testing.T) {
	t.Parallel()
	testname := "generateSignupTokenSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.GenerateSignupTokenS.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		createAllowView := false
		createAllowCrete := false
		createAllowDelete := false
		createAllowPermission := false
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.GenerateSignupToken(cl, createAllowView, createAllowCrete, createAllowDelete, createAllowPermission, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.GenerateSignupTokenS.Speed", fmt.Sprintf("Could not get user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.GenerateSignupTokenS.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGetSpeed(t *testing.T) {
	t.Parallel()
	testname := "getSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	id := mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Warning:", "Test.Get.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.Get(cl, id, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.Get.Speed", fmt.Sprintf("Could not get user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.Get.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGetByEmailSpeed(t *testing.T) {
	t.Parallel()
	testname := "getByEmailSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.GetByEmail.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.GetByEmail(cl, seedEmail, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.GetByEmail.Speed", fmt.Sprintf("Could not get user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.GetByEmail.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGetByTokenSpeed(t *testing.T) {
	t.Parallel()
	testname := "getByTokenSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.GetByToken.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.GetByToken(cl, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.GetByToken.Speed", fmt.Sprintf("Could not get user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.GetByToken.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGetAllSpeed(t *testing.T) {
	t.Parallel()
	testname := "getAllSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.GetAll.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err = client.GetAll(cl, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.GetAll.Speed", fmt.Sprintf("Could not get user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.GetAll.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestUpdateProfilSpeed(t *testing.T) {
	t.Parallel()
	testname := "UpdateProfilSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.UpdateProfile.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for i, cl := range clients {
		updateName := fmt.Sprintf("Update User %d", i)
		updateEmail := fmt.Sprintf("updateuser%d@softcorp.io", i)
		updatePhone := "18230123902"
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			err := client.UpdateProfile(cl, updateName, updateEmail, updatePhone, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.Update.Speed", fmt.Sprintf("Could not update user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.UpdateProfile.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestUpdateAllowancesSpeed(t *testing.T) {
	t.Parallel()
	testname := "updateAllowancesSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	id := mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.UpdateAllowances.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		updateAllowView := true
		updateAllowCreate := true
		updateAllowDelete := true
		updateAllowPermission := true
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			err := client.UpdateAllowances(cl, id, updateAllowView, updateAllowCreate, updateAllowDelete, updateAllowPermission, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.UpdateAllowances.Speed", fmt.Sprintf("Could not update user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.UpdateAllowances.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestUpdatePasswordSpeed(t *testing.T) {
	t.Parallel()
	testname := "updatePasswordSpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.UpdatePassword.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		oldPassword := seedPassword
		newPassword := seedPassword
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			err := client.UpdatePassword(cl, oldPassword, newPassword, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.UpdatePassword.Speed", fmt.Sprintf("Could not update user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.UpdatePassword.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}

func TestGetAuthHistorySpeed(t *testing.T) {
	t.Parallel()
	testname := "getAuthHistorySpeed"
	os.Mkdir("./results/"+testname, 0777)
	f, err := os.Create("./results/" + testname + "/testlogfile.yaml")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)
	// configure
	mock.TruncateUsers()

	seedName := "Seed User"
	seedEmail := "seeduser@softcorp.io"
	seedPassword := "RandomPassword1234"
	seedPhone := "+45 88 88 88 88"
	seedAllowView := true
	seedAllowCreate := true
	seedAllowDelete := true
	seedAllowPermission := true
	_ = mock.Seed(seedName, seedEmail, seedPhone, seedPassword, seedAllowView, seedAllowCreate, seedAllowPermission, seedAllowDelete)

	initialTime := time.Now()

	// concurrenctly set up amount clinents
	var wgConnection sync.WaitGroup
	var clients []proto.UserServiceClient
	var conns []*grpc.ClientConn
	for i := 1; i <= amount; i++ {
		wgConnection.Add(1)
		go func(wg *sync.WaitGroup) {
			var conn *grpc.ClientConn
			for {
				tempConn, err := grpc.Dial(":9091", grpc.WithInsecure())
				if err == nil {
					conn = tempConn
					break
				}
			}
			conns = append(conns, conn)
			client := proto.NewUserServiceClient(conn)
			clients = append(clients, client)
			wg.Done()
		}(&wgConnection)
	}
	// wait for them to be done
	wgConnection.Wait()

	var wgAuth sync.WaitGroup
	wgAuth.Add(1)
	token, err := client.Auth(clients[0], seedEmail, seedPassword, &wgAuth)
	if err != nil {
		log.Fatal("Fatal:", "Test.AuthHistory.Speed", "Could not authenticate")
	}
	wgAuth.Wait()

	// apply connections to clients
	var wgClient sync.WaitGroup
	for _, cl := range clients {
		go func(wg *sync.WaitGroup) {
			wg.Add(1)
			_, err := client.GetAuthHistory(cl, token, wg)
			if err != nil {
				log.Println("Warning:", "Test.AuthHistory.Speed", fmt.Sprintf("Could not update user with err %v", err))
			}
		}(&wgClient)
	}
	wgClient.Wait()

	dur := time.Now().Sub(initialTime)

	// close connections
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			log.Println("Warning:", "Test.AuthHistory.Speed", "Could close client connection")
		}
	}

	result := fmt.Sprintf("We applied: %d clients in %s which results in an average time of: %f milliseconds", amount, dur.String(), float64(dur.Milliseconds())/float64(amount))
	log.Println(result)
	resultToFile(testname, result)
}
